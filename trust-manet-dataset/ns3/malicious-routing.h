/*
 * TRUST-MANET : malicious-routing.h
 * ---------------------------------
 * A thin subclass of ns3::aodv::RoutingProtocol that injects forwarding
 * misbehaviour for a selected set of "compromised" nodes:
 *
 *   BLACKHOLE  -> drop ALL transit (forwarded) application data packets.
 *   GRAYHOLE   -> drop transit application data packets with probability p.
 *   NONE       -> behave exactly like stock AODV (benign node).
 *
 * Only the *data-forwarding* path is altered. All AODV control logic
 * (RREQ/RREP/RERR, route table, local delivery) is inherited unchanged,
 * so routing still converges and the misbehaviour is observable purely as
 * a forwarding anomaly -- which is exactly the signal the local IDS in the
 * TRUST-MANET proposal is meant to detect, separated from mobility loss.
 *
 * NOTE on attack *attraction*: a full blackhole also spoofs RREPs (high dst
 * seqno, hop-count 1) to attract traffic. That requires editing AODV's
 * RecvRequest/SendReply and is version-specific. This file deliberately
 * implements the lower-risk, version-stable *drop* behaviour only. See
 * README.md "Optional: RREP-spoofing attraction" for how to add it.
 *
 * Targeted ns-3 version: ns-3.42 (public Ipv4RoutingProtocol / aodv API).
 */
#ifndef TRUST_MANET_MALICIOUS_ROUTING_H
#define TRUST_MANET_MALICIOUS_ROUTING_H

#include "ns3/aodv-routing-protocol.h"
#include "ns3/random-variable-stream.h"
#include "ns3/nstime.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv4-route.h"

namespace ns3
{

class MaliciousRouting : public aodv::RoutingProtocol
{
  public:
    enum AttackType
    {
        NONE = 0,
        BLACKHOLE = 1,
        GRAYHOLE = 2
    };

    static TypeId GetTypeId();
    MaliciousRouting();
    ~MaliciousRouting() override;

    /** Configure this node as an attacker. dropProb only used for GRAYHOLE. */
    void SetAttack(AttackType type, double dropProb, Time start, Time stop);

    /** Overridden forwarding decision. */
    bool RouteInput(Ptr<const Packet> p,
                    const Ipv4Header& header,
                    Ptr<const NetDevice> idev,
                    const UnicastForwardCallback& ucb,
                    const MulticastForwardCallback& mcb,
                    const LocalDeliverCallback& lcb,
                    const ErrorCallback& ecb) override;

    // --- cumulative counters, read (as deltas) once per measurement window ---
    uint64_t m_recvForward = 0;   // transit data packets that reached the forwarding hook
    uint64_t m_fwdOk = 0;         // transit data packets actually forwarded
    uint64_t m_fwdDropAttack = 0; // transit data packets dropped by the attack
    uint64_t m_noRoute = 0;       // ErrorCallback invocations (no route / route break)

    AttackType GetAttackType() const { return m_attack; }

  private:
    // Static hooks are bound (via MakeBoundCallback) with `this` + the original
    // callback, so they match the exact ns-3 callback signatures.
    static void ForwardHook(MaliciousRouting* self,
                            UnicastForwardCallback ucb,
                            Ptr<Ipv4Route> route,
                            Ptr<const Packet> p,
                            const Ipv4Header& header);

    static void ErrorHook(MaliciousRouting* self,
                          ErrorCallback ecb,
                          Ptr<const Packet> p,
                          const Ipv4Header& header,
                          Socket::SocketErrno err);

    bool AttackActiveNow() const;

    AttackType m_attack = NONE;
    double m_dropProb = 0.0;
    Time m_start = Seconds(0);
    Time m_stop = Seconds(0);
    Ptr<UniformRandomVariable> m_rng;
};

} // namespace ns3

#endif // TRUST_MANET_MALICIOUS_ROUTING_H
