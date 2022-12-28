In this program assignment, we start from some code skeleton provided by instructors and develop a simple router (SR) with a static routing table. Our router can receive raw Ethernet frames, process the packets like a real router, and forward them to the correct outgoing interface.



We are responsible for implementing the logic to handle incoming Ethernet frames (ICMP, ARP, IP….), including forward or drop packet, generate ICMP echo reply messages, handle ARP requests and replies, and so on.



The emulated topology on which our simple router (SR) runs is shown below.

![Screenshot 2022-12-28 at 5.24.47 PM](/Users/sidaxiong/Desktop/Screenshot 2022-12-28 at 5.24.47 PM.png)