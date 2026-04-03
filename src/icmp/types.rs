/// ICMP (Internet Control Message Protocol) — What is it?
///
/// When computers communicate over the internet, they use IP (Internet Protocol) to send
/// packets of data from source to destination. But IP itself has no way to say "hey,
/// something went wrong" or "are you alive?" — that's what ICMP is for.
///
/// ICMP is a companion protocol to IP. It's used by routers and hosts (computers) to
/// send short diagnostic messages about the state of the network. Think of it as the
/// "error reporting" and "health check" layer of the internet.
///
/// Every ICMP message has two identifying numbers:
///   - `type` : the broad category of the message (e.g. "Destination Unreachable")
///   - `code` : a sub-reason within that category (e.g. "Port is unreachable")
///
/// This enum maps every (type, code) pair into a named Rust variant, so you never
/// have to work with raw numbers in your application logic
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IcmpType {
  // =========================================================================
  // TYPE 0 — Echo Reply
  // =========================================================================
  /// The other side is alive and answered our ping.
  ///
  /// Background:
  ///   The `ping` tool works by sending an "Echo Request" (type 8) to a target
  ///   host. If the host is up and reachable, it replies with this message.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - The remote host is reachable and responding normally.
  ///   - This is the successful response to a ping you sent.
  ///   - You can measure round-trip time (RTT) from when you sent the request
  ///     to when this reply arrived.
  ///
  /// WHEN YOU SEND IT:
  ///   - Your OS sends this automatically when someone pings your machine.
  ///   - You don't usually craft this manually — the kernel handles it.
  EchoReply,
  // =========================================================================
  // TYPE 3 — Destination Unreachable
  // =========================================================================
  /// The packet could not be delivered and was dropped.
  ///
  /// Background:
  ///   When a router or the destination host cannot deliver a packet, it sends
  ///   this message back to the original sender. The `code` field specifies
  ///   the exact reason why delivery failed. This is one of the most important
  ///   ICMP types for network debugging — it tells you *why* your packet didn't
  ///   arrive, not just that it didn't.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - Your packet was dropped somewhere along the way.
  ///   - Check the inner `DestinationUnreachableCode` for the specific reason
  ///     (wrong port, blocked by firewall, no route, etc.).
  ///
  /// WHEN YOU SEND IT (or rather, when a router/host sends it):
  ///   - A router sends this if it has no route to the destination network.
  ///   - The destination host sends this if the target port has no listener
  ///     (e.g. nothing is running on that TCP/UDP port).
  ///   - A firewall may send this to actively reject connections.
  DestinationUnreachable(DestinationUnreachableCode),
  // =========================================================================
  // TYPE 4 — Source Quench (DEPRECATED — never use)
  // =========================================================================
  /// An obsolete "slow down, you're sending too fast" signal.
  ///
  /// Background:
  ///   In the early days of the internet, if a router was overwhelmed with
  ///   traffic and dropping packets, it could send this message back to the
  ///   sender saying "please reduce your transmission rate." Modern TCP/IP
  ///   stacks handle congestion control internally (through mechanisms like
  ///   TCP slow-start and ECN — Explicit Congestion Notification), so this
  ///   ICMP type became redundant and was officially deprecated in RFC 6633.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - Almost never in practice. If you do, it's from legacy hardware.
  ///   - Modern hosts are required to ignore this message.
  ///
  /// WHEN YOU SEND IT:
  ///   - Never. Do not implement or use this
  #[deprecated(note = "Never used in modern systems, Ignore if received. (Deprecated by RFC 663)")]
  SourceQuench,
  // =========================================================================
  // TYPE 5 — Redirect
  // =========================================================================
  /// A router is telling you: "use a different, better route for this traffic."
  ///
  /// Background:
  ///   When your computer sends a packet, it goes to your default gateway
  ///   (usually your home router). That router might know that a *different*
  ///   gateway would be a more efficient path to the destination. Rather than
  ///   silently rerouting, the router forwards your packet AND sends this
  ///   ICMP Redirect back to you, so your machine can update its routing
  ///   table and send future packets directly to the better gateway.
  ///
  ///   Example: You're at `192.168.1.10`, default gateway is `192.168.1.1`.
  ///   You send traffic to `10.0.0.5`. Your gateway knows that `192.168.1.2`
  ///   has a direct route to that subnet, so it sends you a Redirect saying
  ///   "for traffic to 10.0.0.5, use 192.168.1.2 instead."
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - A router is suggesting a better next-hop for your packets.
  ///   - Your OS may automatically update its routing table for that destination.
  ///   - Security note: Redirect messages can be spoofed to hijack traffic.
  ///     Many security-hardened systems (Linux with `net.ipv4.conf.all.accept_redirects=0`)
  ///     disable accepting ICMP Redirects entirely.
  ///
  /// WHEN YOU SEND IT (i.e., when a router sends it):
  ///   - Sent by a router that forwarded your packet but knows a shorter path exists.
  Redirect(RedirectCode),
  // =========================================================================
  // TYPE 8 — Echo Request (Ping)
  // =========================================================================
  /// "Are you there?" — the outgoing half of a ping.
  ///
  /// Background:
  ///   This is what `ping` sends. The sender puts a sequence number and timestamp
  ///   in the payload, and the receiver is expected to reflect it back in an
  ///   Echo Reply (type 0). By comparing the timestamps, you can measure network
  ///   latency (round-trip time) and packet loss.
  ///
  ///   This is also used by network scanners (like nmap) to discover which
  ///   hosts are online on a network — sometimes called "ping sweep."
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - Someone is pinging your machine to check if it's alive.
  ///   - Your OS will automatically respond with EchoReply (type 0) if the
  ///     firewall allows it.
  ///   - Security note: Servers often block incoming ICMP Echo Requests to
  ///     prevent network mapping by attackers.
  ///
  /// WHEN YOU SEND IT:
  ///   - You are pinging a remote host (e.g. `ping 8.8.8.8`).
  Echo,
  // =========================================================================
  // TYPE 9 — Router Advertisement
  // =========================================================================
  /// A router is announcing its presence to hosts on the local network.
  ///
  /// Background:
  ///   Routers periodically broadcast this message to tell nearby hosts:
  ///   "I exist, and I am a valid gateway you can use to reach other networks."
  ///   This is part of the ICMP Router Discovery Protocol (IRDP, RFC 1256).
  ///   Hosts can use this to automatically configure their default gateway
  ///   without needing a DHCP server.
  ///
  ///   Note: In IPv6, Router Advertisement is a core part of NDP (Neighbor
  ///   Discovery Protocol) and is far more heavily used than in IPv4.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - A router nearby is advertising itself as a gateway.
  ///   - Your OS may use this to populate its routing table.
  ///
  /// WHEN YOU SEND IT:
  ///   - Routers send this periodically (every few minutes) and in response
  ///     to a Router Solicitation (type 10).
  RouterAdvertisement,
  // =========================================================================
  // TYPE 10 — Router Solicitation / Selection (RARE / DEPRECATED)
  // =========================================================================
  /// A host asking "is there a router nearby?"
  ///
  /// Background:
  ///   This is the counterpart to Router Advertisement. A newly connected host
  ///   can send this message to quickly discover nearby routers without waiting
  ///   for the next periodic advertisement. Rarely seen in modern IPv4 networks,
  ///   but relevant in IPv6 (where it's part of NDP).
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - A host on the local network wants to discover routers.
  ///   - Routers should respond with a Router Advertisement (type 9).
  ///
  /// WHEN YOU SEND IT:
  ///   - Sent by a host immediately after it connects to a network.
  #[deprecated(note = "Rare in modern IPv4 networks. More relevant in IPv6 NDP context.")]
  RouterSolicitation,
  // =========================================================================
  // TYPE 11 — Time Exceeded
  // =========================================================================
  /// A packet's TTL hit zero and was discarded, or reassembly timed out.
  ///
  /// Background:
  ///   Every IP packet carries a TTL (Time To Live) field — a counter that
  ///   starts at some value (typically 64 or 128) and is decremented by 1
  ///   at each router hop. If the TTL reaches zero, the router discards the
  ///   packet and sends this message back to the original sender.
  ///
  ///   This prevents "lost" packets from circulating the internet forever
  ///   in routing loops. It's also the core mechanism behind `traceroute`:
  ///   traceroute sends packets with TTL=1, TTL=2, TTL=3, etc. Each router
  ///   that drops the packet (at TTL=0) sends back a Time Exceeded message,
  ///   revealing its IP address and latency — building a hop-by-hop map
  ///   of the path to the destination.
  ///
  /// WHEN YOU RECEIVE IT (code = TimeToLiveExceededInTransit):
  ///   - A router along the path discarded your packet because TTL hit 0.
  ///   - The source IP in the ICMP message is the router that discarded it.
  ///   - If you're running traceroute, this is the expected and desired response
  ///     at each hop — you're using TTL expiry to map the route.
  ///   - If you're NOT running traceroute, this means your TTL was set too low
  ///     for the packet to reach its destination.
  ///
  /// WHEN YOU RECEIVE IT (code = FragmentReassemblyTimeExceeded):
  ///   - A large packet was split into fragments for transit, but not all
  ///     fragments arrived in time to be reassembled at the destination.
  ///   - The destination host discarded the partial packet and sent this reply.
  ///
  /// WHEN YOU SEND IT (i.e., when a router sends it):
  ///   - A router decremented TTL to 0, discarded the packet, and is notifying
  ///     the original sender.
  TimeExceeded(TimeExceededCode),
  // =========================================================================
  // TYPE 12 — Parameter Problem
  // =========================================================================
  /// The IP header of your packet contained an error and could not be processed.
  ///
  /// Background:
  ///   IP packets have a header section with various fields (source/destination
  ///   address, protocol, options, etc.). If a router or host receives a packet
  ///   with a malformed, invalid, or missing header field, it sends this message
  ///   back. The `pointer` field in the ICMP payload points to the exact byte
  ///   in the original header that caused the problem.
  ///
  ///   This is rare in normal traffic but can appear when:
  ///   - Crafting raw packets manually (e.g. in security research or networking tools).
  ///   - A bug in a network stack generates malformed packets.
  ///   - Malformed IP options are used.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - One of your packets had an invalid IP header and was rejected.
  ///   - The specific `ParameterProblemCode` and the pointer offset tell you
  ///     which field was wrong.
  ///   - This almost always indicates a bug in the sending software.
  ///
  /// WHEN YOU SEND IT (i.e., when a router/host sends it):
  ///   - The received packet's header was too broken to process.
  ParameterProblem(ParameterProblemCode),
  // =========================================================================
  // TYPE 13 — Timestamp Request
  // =========================================================================
  /// A request to synchronize clocks or measure one-way delay between two hosts.
  ///
  /// Background:
  ///   Similar to Echo Request/Reply, but instead of generic data, the payload
  ///   contains timestamps. The sender includes its "originate time," and the
  ///   receiver fills in "receive time" and "transmit time" before sending back
  ///   a Timestamp Reply (type 14). This can theoretically be used for clock
  ///   synchronization, though NTP is used for this in practice.
  ///
  ///   Security note: Timestamp requests can reveal a host's system clock, which
  ///   may leak OS version or uptime information. Many firewalls block type 13/14.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - A remote host wants to compare clock times or measure transit delay.
  ///   - You should respond with a Timestamp Reply (type 14) if you support it.
  ///
  /// WHEN YOU SEND IT:
  ///   - You want to measure clock offset or one-way delay to a remote host.
  Timestamp,
  // =========================================================================
  // TYPE 14 — Timestamp Reply
  // =========================================================================
  /// The response to a Timestamp Request, carrying the receiver's clock readings.
  ///
  /// Background:
  ///   Sent in response to a Timestamp Request (type 13). The reply includes
  ///   three 32-bit timestamps: originate (from the requester), receive (when
  ///   the replier got the request), and transmit (when the replier sent this).
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - This is the response to a Timestamp Request you sent.
  ///   - By comparing the four timestamps (your send time + the three in the reply)
  ///     you can estimate clock offset and one-way delay.
  ///
  /// WHEN YOU SEND IT:
  ///   - Sent in response to an incoming Timestamp Request (type 13).
  TimestampReply,
  // =========================================================================
  // TYPE 15 — Information Request (DEPRECATED)
  // =========================================================================
  /// An ancient mechanism for a host to discover its own IP address.
  ///
  /// Background:
  ///   In the very early internet (before DHCP, before BOOTP), a diskless
  ///   workstation booting from the network had no way to know its own IP
  ///   address. It could send this request (with source IP = 0.0.0.0) and a
  ///   server would reply with the address it should use. This is entirely
  ///   obsolete — DHCP handles address assignment in all modern networks.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - A legacy device is trying to discover its IP address.
  ///   - No modern system should send or handle this.
  ///
  /// WHEN YOU SEND IT:
  ///   - Never. Use DHCP.
  #[deprecated(note = "Replaced by DHCP/BOOTP. No modern system uses this.")]
  InformationRequest,
  // =========================================================================
  // TYPE 16 — Information Reply (DEPRECATED)
  // =========================================================================
  /// The response to an Information Request, providing the requester's IP address.
  ///
  /// Background:
  ///   Counterpart to Information Request (type 15). Equally obsolete.
  ///   See the notes on InformationRequest above.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - A legacy system responded to your Information Request.
  ///   - Should never appear in modern networks.
  #[deprecated(note = "Replaced by DHCP/BOOTP. No modern system uses this.")]
  InformationReply,
  // =========================================================================
  // TYPE 17 — Address Mask Request
  // =========================================================================
  /// A host asking: "What is the subnet mask for this network?"
  ///
  /// Background:
  ///   A subnet mask tells a host which part of an IP address is the "network
  ///   portion" (shared by all devices in the same local network) and which
  ///   part is the "host portion" (unique to each device). For example, a mask
  ///   of 255.255.255.0 means the first 24 bits are the network.
  ///
  ///   Before DHCP included subnet mask delivery, hosts could use this ICMP
  ///   type to ask a local router for the subnet mask. This is extremely rare
  ///   in modern networks since DHCP provides the mask automatically.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - A device on the local network wants to know the subnet mask.
  ///   - If you are a router, you should respond with an Address Mask Reply (type 18).
  ///
  /// WHEN YOU SEND IT:
  ///   - Your host wants to learn the subnet mask from a router.
  AddressMaskRequest,
  // =========================================================================
  // TYPE 18 — Address Mask Reply
  // =========================================================================
  /// A router's response providing the subnet mask to the requesting host.
  ///
  /// Background:
  ///   Sent by a router in response to an Address Mask Request (type 17).
  ///   The reply contains the 32-bit subnet mask for the local network.
  ///   Like the request, this is largely obsolete thanks to DHCP.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - A router answered your Address Mask Request with the subnet mask.
  ///
  /// WHEN YOU SEND IT:
  ///   - Sent by a router responding to an Address Mask Request.
  AddressMaskReply,
  // =========================================================================
  // TYPE 30 — Traceroute (NON-STANDARD / LEGACY / EXPERIMENTAL)
  // =========================================================================
  /// An experimental, non-standard ICMP type for route tracing. Never widely adopted.
  ///
  /// Background:
  ///   This was an early proposal (RFC 1393) to improve traceroute by having
  ///   routers send ICMP type 30 messages with routing information when they
  ///   forwarded a packet containing a special IP option ("Record Route" option).
  ///   The idea was to get richer routing data than the standard TTL-expiry
  ///   method used by classic traceroute.
  ///
  ///   It was never widely implemented and is considered non-standard.
  ///   Modern `traceroute` and `tracert` still rely on TTL expiry and
  ///   Time Exceeded (type 11) messages, not this type.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - Extremely rare. A legacy or experimental system sent a traceroute
  ///     probe using the old RFC 1393 method.
  ///   - You can largely ignore this in modern implementations.
  ///
  /// WHEN YOU SEND IT:
  ///   - You should not. Use the standard TTL-based traceroute approach.
  #[deprecated(note = "RFC 1393 experimental – never standardised")]
  TracerouteExperimental,
  // =========================================================================
  // UNKNOWN — Unrecognized (type, code) pair
  // =========================================================================
  /// The (type, code) pair does not match any known, standardized ICMP message.
  ///
  /// Background:
  ///   ICMP has room for 256 type values and 256 code values per type. Only a
  ///   small fraction of these are defined in RFCs. The rest may be:
  ///   - Vendor-specific or proprietary extensions.
  ///   - Experimental types from old RFCs that were never standardized.
  ///   - Malformed or intentionally crafted packets (e.g. in fuzzing or attacks).
  ///   - Future ICMP types not yet known at the time this code was written.
  ///
  /// WHEN YOU RECEIVE IT:
  ///   - Something sent an ICMP message your parser doesn't recognize.
  ///   - The inner `(u8, u8)` tuple holds the raw (type, code) values so you
  ///     can log them, inspect them, or handle them manually if needed.
  ///   - In most applications, you would log a warning and discard the packet.
  ///
  /// WHEN YOU ENCOUNTER IT IN CODE:
  ///   - Pattern match on this variant to handle unknown types gracefully
  ///     rather than panicking or silently dropping diagnostic information.
  Unknown((u8, u8)),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParameterProblemCode {
  /// The "pointer" field in the ICMP message points to a specific byte
  /// in the original IP header that caused the problem.
  ///
  /// Example: pointer = 12 means byte 12 of the IP header is invalid.
  /// This is the most common and informative sub-code — it tells you exactly
  /// which field was broken.
  PointerIndicatesTheError,
  /// A required IP option was expected but not present in the header.
  ///
  /// IP headers can carry optional fields for things like source routing,
  /// record route, timestamps, etc. Some network paths or protocols require
  /// specific options to be present. If a required option is missing,
  /// this code is used.
  MissingRequiredOption,
  /// The total length field in the IP header does not match the actual
  /// size of the packet received.
  ///
  /// For example, the header says the packet is 200 bytes long, but only
  /// 150 bytes arrived — or the length field is mathematically impossible
  /// given the header size. This almost always indicates a software bug
  /// or packet corruption in transit.
  BadLength,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeExceededCode {
  /// The packet's TTL (Time To Live) counter was decremented to zero at
  /// an intermediate router and the packet was discarded.
  ///
  /// How TTL works:
  ///   Every IP packet starts with a TTL value (commonly 64 or 128 on Linux/Windows).
  ///   Each router that forwards the packet subtracts 1 from the TTL. When TTL
  ///   reaches 0, the router drops the packet and sends this ICMP message back
  ///   to the original sender. This prevents routing loops from sending packets
  ///   circling around the internet forever.
  ///
  /// How traceroute exploits this:
  ///   `traceroute` sends a probe with TTL=1 (dropped at hop 1), then TTL=2
  ///   (dropped at hop 2), and so on. Each router that drops a packet reveals
  ///   its IP address in the ICMP reply, letting traceroute reconstruct the
  ///   full network path to the destination.
  TimeToLiveExceededInTransit,
  /// Not all fragments of a fragmented packet arrived in time for reassembly
  /// at the destination, so the partial packet was discarded.
  ///
  /// How IP fragmentation works:
  ///   When a packet is too large to fit through a network link in one piece
  ///   (each link has a maximum transmission unit, or MTU), it gets split
  ///   into smaller fragments. Each fragment is sent independently and may
  ///   take different paths. The destination host collects all fragments and
  ///   reassembles the original packet.
  ///
  ///   If any fragment doesn't arrive within a timeout window (typically
  ///   15–60 seconds), the destination gives up, discards the partial data,
  ///   and sends this ICMP message back to the original sender.
  ///
  ///   This can happen during high packet loss, asymmetric routing, or when
  ///   a fragment is dropped by a firewall.
  FragmentReassemblyTimeExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectCode {
  /// Use the new gateway for ALL traffic destined to the entire target
  /// network (or subnet), regardless of protocol or service.
  ///
  /// Example: All packets going to 10.20.0.0/24 should now go through
  /// the new gateway, not your default gateway.
  RedirectDatagramForTheNetworkOrSubnet,
  /// Use the new gateway only for traffic destined to one specific
  /// host IP address, not an entire network.
  ///
  /// Example: Only packets going to 10.20.0.5 specifically should
  /// use the new route. Packets to 10.20.0.6 still go the old way.
  RedirectDatagramForTheHost,
  /// Use the new gateway for traffic to the entire target network,
  /// but only for a specific Type of Service (ToS) value.
  ///
  /// ToS (now largely replaced by DSCP/DiffServ) was an IP header field
  /// used to prioritize certain traffic (e.g. voice, video, bulk transfers).
  /// This redirect applies only to traffic with a matching ToS value.
  /// Rarely used in practice.
  RedirectDatagramForTheTypeOfServiceAndNetwork,
  /// Use the new gateway for traffic to a specific host, AND only for
  /// a specific Type of Service (ToS) value.
  ///
  /// The most narrow form of redirect — applies to one specific host
  /// AND one specific traffic class. Very rarely seen.
  RedirectDatagramForTheTypeOfServiceAndHost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestinationUnreachableCode {
  /// No route to the destination *network* exists in the router's routing table.
  ///
  /// Example: You're trying to reach 192.0.2.1, but no router along the path
  /// knows how to forward traffic to the 192.0.2.0/24 network. The router
  /// that encountered the missing route sends this back.
  ///
  /// Implication: The entire destination network is unreachable from your location,
  /// not just a single host. This could be a routing misconfiguration, a network
  /// outage, or an IP range that simply doesn't exist on the public internet.
  NetIsUnreachable,
  /// The destination network is reachable, but the specific host is not responding.
  ///
  /// Example: The router knows how to reach the 192.168.1.0/24 network, but
  /// when it tries to deliver the packet to 192.168.1.50 specifically, it gets
  /// no ARP response (the host isn't there or is powered off).
  ///
  /// Implication: The host is down, disconnected, or doesn't exist at that address.
  /// Other hosts on the same network might be reachable.
  HostIsUnreachable,
  /// The packet used a transport-layer protocol that the destination host
  /// does not support.
  ///
  /// IP packets carry a "protocol" field indicating what's inside (TCP=6,
  /// UDP=17, OSPF=89, etc.). If the destination host receives a packet
  /// using a protocol number it doesn't implement or have enabled,
  /// it sends this response.
  ///
  /// Example: Sending an OSPF packet to a regular Linux server that doesn't
  /// run any OSPF daemon.
  ///
  /// Implication: The host is reachable, but it doesn't speak the protocol
  /// you're trying to use.
  ProtocolIsUnreachable,
  /// The destination host received the packet but nothing is listening on
  /// the target UDP port (TCP uses its own RST mechanism for this).
  ///
  /// Example: You send a UDP packet to port 9999 on a server. If no
  /// application is listening on port 9999, the server's kernel sends
  /// this ICMP message back. (For TCP, a RST packet is sent instead —
  /// TCP doesn't use ICMP for port closed notifications.)
  ///
  /// This is very commonly used by UDP-based port scanners (like nmap)
  /// to determine which UDP ports are closed: a "port unreachable" ICMP
  /// reply means the port is definitely closed, while silence might mean
  /// the port is open (and filtered the probe).
  ///
  /// Implication: The host is up and the network path works, but your
  /// target service is not running.
  PortIsUnreachable,
  /// The packet needed to be fragmented (split into smaller pieces) because
  /// it was too large for a link along the path, but the DF (Don't Fragment)
  /// bit was set in the IP header, forbidding fragmentation.
  ///
  /// Background:
  ///   Every network link has a maximum packet size called the MTU (Maximum
  ///   Transmission Unit). Standard Ethernet MTU is 1500 bytes. If your packet
  ///   is larger, routers must fragment it — UNLESS the sender set the
  ///   "Don't Fragment" (DF) bit, which means "don't split this packet."
  ///   If DF is set and the packet is too big, the router drops the packet
  ///   and sends this response.
  ///
  /// This is a core part of Path MTU Discovery (PMTUD):
  ///   Applications deliberately set DF=1 and send increasingly large packets.
  ///   When this ICMP comes back, the sender knows the maximum packet size for
  ///   that path and adjusts accordingly. This is how TCP efficiently discovers
  ///   the maximum safe packet size for a connection.
  ///
  /// Implication: You need to reduce your packet size (MTU) for this path,
  /// OR remove the DF restriction. The ICMP message typically includes the
  /// MTU of the bottleneck link to help you adjust.
  FragmentationIsNeededAndDontFragmentWasSet,
  /// A source route specified in the IP header (an explicit list of routers
  /// to traverse) could not be followed because one of the hops in the list
  /// is unreachable.
  ///
  /// Source routing is a rarely-used IP feature that lets the sender specify
  /// the exact path a packet must take. If any router in that path is down
  /// or unreachable, forwarding fails and this code is returned.
  ///
  /// Security note: Source routing is widely disabled on the internet today
  /// because it can be abused to bypass firewalls or perform traffic hijacking.
  SourceRouteFailed,
  /// The destination network exists in no router's table and is completely
  /// unknown to the routing infrastructure.
  ///
  /// Slightly different from `NetIsUnreachable`: here the router is saying
  /// it has never heard of this network at all — it's not that the route is
  /// simply missing from one router's table, the network is globally unknown.
  ///
  /// Example: Sending to an unallocated, non-existent IP range.
  DestinationNetworkIsUnknown,
  /// The destination host's IP address is not recognized — no ARP entry
  /// exists and the host has never been heard from.
  ///
  /// Slightly different from `HostIsUnreachable`: the router or gateway
  /// has no record of this host ever existing, as opposed to a host it
  /// previously knew about that is now unreachable.
  DestinationHostIsUnknown,
  /// The source host is isolated — it is not permitted to communicate
  /// with outside networks.
  ///
  /// This code indicates a routing policy decision: the source host's network
  /// segment is intentionally cut off from the rest of the network
  /// (e.g. quarantined or sandboxed for security reasons).
  ///
  /// bref: if source host is isolcated that mean when host try to reach outside
  /// we receive this icmp code, mean we are not able to connect with outside
  /// may outside can connect with machine if port are allowed...
  ///
  /// Rarely seen in practice.
  SourceHostIsIsolated,
  /// Communication to the destination *network* is blocked by an administrative
  /// policy (e.g. an access control list on a router or firewall).
  ///
  /// Unlike being physically unreachable, this means a network administrator
  /// has explicitly configured a rule that blocks this traffic. The destination
  /// network is reachable in principle, but your traffic is not allowed.
  ///
  /// Example: An enterprise firewall blocking traffic to external network ranges.
  /// This is one of the ICMP codes that explicitly signals a firewall is present.
  CommunicationWithDestinationNetworkIsAdministrativelyProhibited,
  /// Communication to the destination *host* is blocked by an administrative
  /// policy (e.g. a per-host firewall rule).
  ///
  /// Same as above but targeting a specific host rather than a whole network.
  /// The host is reachable at the network level, but policy blocks traffic to it.
  ///
  /// Example: A firewall rule that blocks all traffic to one specific server.
  CommunicationWithDestinationHostIsAdministrativelyProhibited,
  /// The destination network is reachable but not for the requested Type of
  /// Service (ToS) value. A path exists, but not one that satisfies the
  /// quality-of-service requirements specified in the packet.
  ///
  /// ToS / DSCP fields can request certain QoS guarantees (low latency,
  /// high throughput, etc.). If no path supporting that service class
  /// reaches the target network, this code is returned.
  DestinationNetworkIsUnreachableForTypeOfService,
  /// The destination host is reachable but not for the requested Type of
  /// Service value. Same concept as above, but scoped to one specific host.
  DestinationHostIsUnreachableForTypeOfService,
  /// Traffic to this destination is blocked by policy — a catch-all
  /// "administratively prohibited" code.
  ///
  /// This is the most generic form of "firewall rejected your packet."
  /// Unlike the network/host-specific prohibited codes, this one doesn't
  /// specify whether the block is network-wide or host-specific.
  ///
  /// This is what many firewalls and security devices send when they reject
  /// a packet — it's an explicit, honest rejection (as opposed to silently
  /// dropping the packet).
  CommunicationIsAdministrativelyProhibited,
  /// The packet's IP Precedence (priority) field was set higher than this
  /// host is willing to accept from this source.
  ///
  /// IP Precedence is an older priority mechanism (3 bits in the ToS field).
  /// Some networks enforce precedence policies — a low-priority host trying
  /// to send high-precedence traffic might receive this rejection.
  ///
  /// Rarely seen in modern networks. DSCP has largely replaced IP Precedence.
  HostPrecedenceViolation,
  /// The network is currently only accepting traffic above a minimum precedence
  /// threshold, and this packet's priority is below the cutoff.
  ///
  /// Example: During network congestion, a router might enforce a policy that
  /// only high-priority (voice/critical) traffic is forwarded. Low-priority
  /// packets are dropped with this ICMP response.
  ///
  /// Very rarely seen in practice.
  PrecedenceCutoffIsInEffect,
}

// =============================================================================
// Conversion: raw (type, code) numbers → IcmpType enum
// =============================================================================

/// Converts a raw ICMP (type, code) pair into the typed `IcmpType` enum.
///
/// Every ICMP packet on the wire carries two numbers: a `type` byte and a `code` byte.
/// This implementation maps those raw numbers to meaningful Rust variants, so the
/// rest of your application can pattern-match on `IcmpType` instead of magic numbers.
///
/// Usage:
///   ```rust
///   let icmp: IcmpType = (3, 3).into(); // → IcmpType::DestinationUnreachable(PortIsUnreachable)
///   let icmp: IcmpType = (11, 0).into(); // → IcmpType::TimeExceeded(TimeToLiveExceededInTransit)
///   ```
///
/// For types where the code carries no meaningful distinction (e.g. type 0 Echo Reply
/// always means the same thing regardless of code), the code byte is ignored with `_`.
#[allow(deprecated)]
impl From<(u8, u8)> for IcmpType {
  fn from(type_code: (u8, u8)) -> Self {
    match type_code {
      (0, _) => Self::EchoReply,

      (3, 0) => Self::DestinationUnreachable(DestinationUnreachableCode::NetIsUnreachable),
      (3, 1) => Self::DestinationUnreachable(DestinationUnreachableCode::HostIsUnreachable),
      (3, 2) => Self::DestinationUnreachable(DestinationUnreachableCode::ProtocolIsUnreachable),
      (3, 3) => Self::DestinationUnreachable(DestinationUnreachableCode::PortIsUnreachable),
      (3, 4) => Self::DestinationUnreachable(
        DestinationUnreachableCode::FragmentationIsNeededAndDontFragmentWasSet,
      ),
      (3, 5) => Self::DestinationUnreachable(DestinationUnreachableCode::SourceRouteFailed),
      (3, 6) => {
        Self::DestinationUnreachable(DestinationUnreachableCode::DestinationNetworkIsUnknown)
      }
      (3, 7) => Self::DestinationUnreachable(DestinationUnreachableCode::DestinationHostIsUnknown),
      (3, 8) => Self::DestinationUnreachable(DestinationUnreachableCode::SourceHostIsIsolated),
      (3, 9) => Self::DestinationUnreachable(
        DestinationUnreachableCode::CommunicationWithDestinationNetworkIsAdministrativelyProhibited,
      ),
      (3, 10) => Self::DestinationUnreachable(
        DestinationUnreachableCode::CommunicationWithDestinationHostIsAdministrativelyProhibited,
      ),
      (3, 11) => Self::DestinationUnreachable(
        DestinationUnreachableCode::DestinationNetworkIsUnreachableForTypeOfService,
      ),
      (3, 12) => Self::DestinationUnreachable(
        DestinationUnreachableCode::DestinationHostIsUnreachableForTypeOfService,
      ),
      (3, 13) => Self::DestinationUnreachable(
        DestinationUnreachableCode::CommunicationIsAdministrativelyProhibited,
      ),
      (3, 14) => Self::DestinationUnreachable(DestinationUnreachableCode::HostPrecedenceViolation),
      (3, 15) => {
        Self::DestinationUnreachable(DestinationUnreachableCode::PrecedenceCutoffIsInEffect)
      }

      (4, _) => Self::SourceQuench,

      (5, 0) => Self::Redirect(RedirectCode::RedirectDatagramForTheNetworkOrSubnet),
      (5, 1) => Self::Redirect(RedirectCode::RedirectDatagramForTheHost),
      (5, 2) => Self::Redirect(RedirectCode::RedirectDatagramForTheTypeOfServiceAndNetwork),
      (5, 3) => Self::Redirect(RedirectCode::RedirectDatagramForTheTypeOfServiceAndHost),

      (8, _) => Self::Echo,
      (9, _) => Self::RouterAdvertisement,
      (10, _) => Self::RouterSolicitation,

      (11, 0) => Self::TimeExceeded(TimeExceededCode::TimeToLiveExceededInTransit),
      (11, 1) => Self::TimeExceeded(TimeExceededCode::FragmentReassemblyTimeExceeded),

      (12, 0) => Self::ParameterProblem(ParameterProblemCode::PointerIndicatesTheError),
      (12, 1) => Self::ParameterProblem(ParameterProblemCode::MissingRequiredOption),
      (12, 2) => Self::ParameterProblem(ParameterProblemCode::BadLength),

      (13, _) => Self::Timestamp,
      (14, _) => Self::TimestampReply,
      (15, _) => Self::InformationRequest,
      (16, _) => Self::InformationReply,
      (17, _) => Self::AddressMaskRequest,
      (18, _) => Self::AddressMaskReply,

      (30, _) => Self::TracerouteExperimental,

      other => Self::Unknown(other),
    }
  }
}
