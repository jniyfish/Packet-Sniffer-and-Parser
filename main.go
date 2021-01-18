package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "log"
    "time"
)

var (
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 0 * time.Second
    handle       *pcap.Handle
)

func main() {
    //find device
    devices, err := pcap.FindAllDevs()
    device :=""
    //print device
    num := 0
    for _, device := range devices {
        fmt.Printf("%d Name: %s\n", num,device.Name)
        num = num  +1
    }
    //choose device
    chs :=-1
    fmt.Scanf("%d", &chs)
    device = devices[chs].Name
    fmt.Printf("Start listening at $%s\n", device)
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    // Use the handle as a packet source to process all packets
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    pnum:=1
    for packet := range packetSource.Packets() {
        // Process packet here
        fmt.Printf("\nPacket Num [%d]\n", pnum)
        pnum = pnum+1
        printPacketInfo(packet)
    }
}

func printPacketInfo(packet gopacket.Packet) {
    // Let's see if the packet is an ethernet packet
    ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
        fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
        fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
        // Ethernet type is typically IPv4 but could be ARP or other
        fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
    }

    // Let's see if the packet is IP (even though the ether type told us)
    ipLayer := packet.Layer(layers.LayerTypeIPv4)
    if ipLayer != nil {
        ip, _ := ipLayer.(*layers.IPv4)
        fmt.Printf("Src IP %s\n", ip.SrcIP)
        fmt.Printf("Dst IP %s\n", ip.DstIP)
    }

    // Let's see if the packet is UDP
    udpLayer := packet.Layer(layers.LayerTypeUDP)
    if udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
        fmt.Printf("UDP Src port %d\n", udp.SrcPort)
        fmt.Printf("UDP Dst port %d\n", udp.DstPort)
    }

    vxlanLayer := packet.Layer(layers.LayerTypeVXLAN)
    if vxlanLayer != nil {
        vxlan, _ := vxlanLayer.(*layers.VXLAN)
        fmt.Printf("VNI = %d\n", vxlan.VNI)
    }

    greLayer := packet.Layer(layers.LayerTypeGRE)
    if greLayer != nil {
        gre, _ := greLayer.(*layers.GRE)
        fmt.Println("Protocol: ", gre.Protocol)
    }

    // Iterate over all layers, printing out each layer type
    /*fmt.Println("All packet layers:")
    for _, layer := range packet.Layers() {
        fmt.Println("- ", layer.LayerType())
    }*/

    // Check for errors
    if err := packet.ErrorLayer(); err != nil {
        fmt.Println("Error decoding some part of the packet:", err)
    }
}