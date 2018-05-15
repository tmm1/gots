/*
MIT License

Copyright 2016 Comcast Cable Communications Management, LLC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// package main contains CLI utilities for testing
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Comcast/gots"
	"github.com/Comcast/gots/ebp"
	"github.com/Comcast/gots/packet"
	"github.com/Comcast/gots/packet/adaptationfield"
	"github.com/Comcast/gots/pes"
	"github.com/Comcast/gots/psi"
	"github.com/Comcast/gots/scte35"
)

// main parses a ts file that is provided with the -f flag
func main() {
	fileName := flag.String("f", "", "Required: Path to TS file to read")
	outName := flag.String("o", "", "Path to TS file to write")
	showPmt := flag.Bool("pmt", true, "Output PMT info")
	showEbp := flag.Bool("ebp", false, "Output EBP info. This is a lot of info")
	showTiming := flag.Bool("timing", false, "Output timing info")
	dumpSCTE35 := flag.Bool("scte35", false, "Output SCTE35 signals and info.")
	showPacketNumberOfPID := flag.Int("pid", 0, "Dump the contents of the first packet encountered on PID to stdout")
	flag.Parse()
	if *fileName == "" {
		flag.Usage()
		return
	}
	tsFile, err := os.Open(*fileName)
	if err != nil {
		printlnf("Cannot access test asset %s.", fileName)
		return
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Println("Cannot close File", file.Name(), err)
		}
	}(tsFile)
	// Verify if sync-byte is present and seek to the first sync-byte
	reader := bufio.NewReader(tsFile)
	_, err = packet.Sync(reader)
	if err != nil {
		fmt.Println(err)
		return
	}
	pat, err := psi.ReadPAT(reader)
	if err != nil {
		println(err)
		return
	}
	printPat(pat)

	var pmts []psi.PMT
	pm := pat.ProgramMap()
	for pn, pid := range pm {
		if pn == 0 {
			// invalid program in PAT
			continue
		}
		pmt, err := psi.ReadPMT(reader, pid)
		if err != nil {
			panic(err)
		}
		pmts = append(pmts, pmt)
		if *showPmt {
			printPmt(pn, pmt)
		}
	}

	pkt := make(packet.Packet, packet.PacketSize)
	var numPackets uint64
	ebps := make(map[uint64]ebp.EncoderBoundaryPoint)
	scte35PIDs := make(map[uint16]bool)
	if *dumpSCTE35 {
		for _, pmt := range pmts {
			for _, es := range pmt.ElementaryStreams() {
				if es.StreamType() == psi.PmtStreamTypeScte35 {
					scte35PIDs[es.ElementaryPid()] = true
					break
				}

			}
		}
	}

	var outFile *os.File
	if *outName != "" {
		outFile, err = os.OpenFile(*outName, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
		if err != nil {
			printlnf("Cannot open output file %s: %v", *outFile, err)
			return
		}
		defer outFile.Close()
	}

	var prevPCR, prevNewPCR uint64
	prevPTS := make(map[uint16]uint64, 0)
	var currentOffset, lastOffset int64

	for {
		if _, err := io.ReadFull(reader, pkt); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			println(err)
			return
		}
		numPackets++
		if *dumpSCTE35 {
			currPID, err := packet.Pid(pkt)
			if err != nil {
				printlnf("Cannot get packet PID for %d", currPID)
				continue
			}
			if scte35PIDs[currPID] {
				pay, err := packet.Payload(pkt)
				if err != nil {
					printlnf("Cannot get payload for packet number %d on PID %d Error=%s", numPackets, currPID, err)
					continue
				}
				msg, err := scte35.NewSCTE35(pay)
				if err != nil {
					printlnf("Cannot parse SCTE35 Error=%v", err)
					continue
				}
				printSCTE35(currPID, msg)

			}

		}
		if *showEbp {
			ebpBytes, err := adaptationfield.EncoderBoundaryPoint(pkt)
			if err != nil {
				// Not an EBP
				continue
			}
			buf := bytes.NewBuffer(ebpBytes)
			boundaryPoint, err := ebp.ReadEncoderBoundaryPoint(buf)
			if err != nil {
				fmt.Printf("EBP construction error %v", err)
				continue
			}
			ebps[numPackets] = boundaryPoint
			printlnf("Packet %d contains EBP %+v", numPackets, boundaryPoint)
		}
		if *showPacketNumberOfPID != 0 {
			pid := uint16(*showPacketNumberOfPID)
			pktPid, err := packet.Pid(pkt)
			if err != nil {
				continue
			}
			if pktPid == pid {
				printlnf("First Packet of PID %d contents: %x", pid, pkt)
				break
			}
		}
		if *showTiming {
			currPID, _ := packet.Pid(pkt)
			if ad, _ := packet.ContainsAdaptationField(pkt); ad {
				if adaptationfield.HasPCR(pkt) {
					pcrBytes, _ := adaptationfield.PCR(pkt)
					pcr := gots.ExtractPCR(pcrBytes)

					if prevPCR == 0 && currentOffset == 0 {
						currentOffset = -int64(pcr) + (1 * gots.PcrClockRate)
					} else if prevPCR != 0 && (pcr > prevPCR+2*gots.PcrClockRate || pcr < prevPCR) {
						printlnf("PCR discontinuity detected! (%v -> %v)", prevPCR, pcr)
						lastOffset = currentOffset
						currentOffset = -int64(pcr) + int64(prevNewPCR) + (0.25 * gots.PcrClockRate)
					}
					prevPCR = pcr

					newPCR := gots.PCR(pcr).Add(gots.PCR(currentOffset))
					gots.InsertPCR(pcrBytes, uint64(newPCR))
					prevNewPCR = uint64(newPCR)

					printlnf("pid %v: PCR = %.4f -> %.4f (%v -> %v)", currPID, float64(pcr)/gots.PcrClockRate, float64(newPCR)/gots.PcrClockRate, pcr, newPCR)
				}
			}

			if es, err := packet.PESHeader(pkt); err == nil {
				h, err := pes.NewPESHeader(es)
				if err == nil && h.HasPTS() {
					pts := h.PTS()

					prev := prevPTS[currPID]
					if prevPCR == 0 && currentOffset == 0 {
						currentOffset = -int64(pts*300) + (1 * gots.PcrClockRate)
					}
					if prev != 0 && (pts > prev+gots.PtsClockRate || pts < prev-gots.PtsClockRate) {
						printlnf("PTS discontinuity detected!")
					}
					prevPTS[currPID] = pts

					newPTS := gots.PTS(pts).Add(gots.PTS(currentOffset / 300))
					if prevNewPCR != 0 && uint64(newPTS) > (prevNewPCR/300)+2*gots.PtsClockRate {
						newPTS = gots.PTS(pts).Add(gots.PTS(lastOffset / 300))
					}
					gots.InsertPTS(es[9:14], uint64(newPTS))
					printlnf("pid %v: PTS = %.4f -> %.4f (%v -> %v)", currPID, float64(pts)/gots.PtsClockRate, float64(newPTS)/gots.PtsClockRate, pts, newPTS)

				}
				if err == nil && h.HasDTS() && h.DTS() != 0 {
					dts := h.DTS()

					newDTS := gots.PTS(dts).Add(gots.PTS(currentOffset / 300))
					if uint64(newDTS) > (prevNewPCR/300)+2*gots.PtsClockRate {
						newDTS = gots.PTS(dts).Add(gots.PTS(lastOffset / 300))
					}
					gots.InsertPTS(es[14:19], uint64(newDTS))

					printlnf("pid %v: DTS = %.4f -> %.4f (%v -> %v)", currPID, float64(dts)/gots.PtsClockRate, float64(newDTS)/gots.PtsClockRate, dts, newDTS)
				}
			}
		}
		if outFile != nil {
			outFile.Write(pkt)
		}
	}
	println()

}

func printSCTE35(pid uint16, msg scte35.SCTE35) {
	printlnf("SCTE35 Message on PID %d", pid)

	printSpliceCommand(msg.CommandInfo())

	insert, ok := msg.CommandInfo().(scte35.SpliceInsertCommand)
	if ok {

		printSpliceInsertCommand(insert)
	}
	for _, segdesc := range msg.Descriptors() {
		printSegDesc(segdesc)
	}

}

func printSpliceCommand(spliceCommand scte35.SpliceCommand) {
	printlnf("\tCommand Type %v", scte35.SpliceCommandTypeNames[spliceCommand.CommandType()])
	if spliceCommand.HasPTS() {

		printlnf("\tPTS %v", spliceCommand.PTS())

	}
}

func printSegDesc(segdesc scte35.SegmentationDescriptor) {
	if segdesc.IsIn() {

		printlnf("\t<--- IN Segmentation Descriptor")
	}
	if segdesc.IsOut() {

		printlnf("\t---> OUT Segmentation Descriptor")
	}

	printlnf("\t\tEvent ID %d", segdesc.EventID())
	printlnf("\t\tType %+v", scte35.SegDescTypeNames[segdesc.TypeID()])
	if segdesc.HasDuration() {

		printlnf("\t\t Duration %v", segdesc.Duration())
	}

}

func printSpliceInsertCommand(insert scte35.SpliceInsertCommand) {
	println("\tSplice Insert Command")
	printlnf("\t\tEvent ID %v", insert.EventID())
	if insert.HasDuration() {
		printlnf("\t\tDuration %v", insert.Duration())

	}
}

func printPmt(pn uint16, pmt psi.PMT) {
	printlnf("Program #%v PMT", pn)
	printlnf("\tPIDs %v", pmt.Pids())
	println("\tElementary Streams")
	for _, es := range pmt.ElementaryStreams() {
		printlnf("\t\tPid %v: StreamType %v: %v", es.ElementaryPid(), es.StreamType(), es.StreamTypeDescription())
		for _, d := range es.Descriptors() {
			printlnf("\t\t\t%+v", d)
		}
	}
}

func printPat(pat psi.PAT) {
	println("Pat")
	printlnf("\tPMT PIDs %v", pat.ProgramMap())
	printlnf("\tNumber of Programs %v", pat.NumPrograms())
}

func printlnf(format string, a ...interface{}) {
	fmt.Printf(format+"\n", a...)
}
