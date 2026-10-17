/*
 * TRUST-MANET : malicious-routing.cc
 * See malicious-routing.h for the design rationale.
 */
#include "malicious-routing.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{

NS_LOG_COMPONENT_DEFINE("MaliciousRouting");
NS_OBJECT_ENSURE_REGISTERED(MaliciousRouting);

TypeId
MaliciousRouting::GetTypeId()
{
    static TypeId tid = TypeId("ns3::MaliciousRouting")
                            .SetParent<aodv::RoutingProtocol>()
                            .SetGroupName("Internet")
                            .AddConstructor<MaliciousRouting>();
    return tid;
}

MaliciousRouting::MaliciousRouting()
{
    // UniformRandomVariable already defaults to the [0, 1) range we need,
    // so there is no need to set Min/Max (which would require ns3/double.h).
    m_rng = CreateObject<UniformRandomVariable>();
}

MaliciousRouting::~MaliciousRouting()
{
}

void
MaliciousRouting::SetAttack(AttackType type, double dropProb, Time start, Time stop)
{
    m_attack = type;
    m_dropProb = dropProb;
    m_start = start;
    m_stop = stop;
}

bool
MaliciousRouting::AttackActiveNow() const
{
    if (m_attack == NONE)
    {
        return false;
    }
    Time now = Simulator::Now();
    return (now >= m_start) && (now < m_stop);
}

void
MaliciousRouting::ForwardHook(MaliciousRouting* self,
                              UnicastForwardCallback ucb,
                              Ptr<Ipv4Route> route,
                              Ptr<const Packet> p,
                              const Ipv4Header& header)
{
    // Only *transit* (forwarded) packets reach a UnicastForwardCallback;
    // locally-delivered packets go through the LocalDeliverCallback and are
    // never affected here.
    self->m_recvForward++;

    // Protocol 17 == UDP. Application data in this framework is UDP CBR;
    // AODV control is sent over AODV's own sockets and is not forwarded via
    // this transit path, so "transit UDP" == application data.
    const bool isData = (header.GetProtocol() == 17);

    if (isData && self->AttackActiveNow())
    {
        bool drop = false;
        if (self->m_attack == BLACKHOLE)
        {
            drop = true;
        }
        else if (self->m_attack == GRAYHOLE)
        {
            drop = (self->m_rng->GetValue() < self->m_dropProb);
        }

        if (drop)
        {
            self->m_fwdDropAttack++;
            // Silently drop: do NOT invoke ucb -> packet is not forwarded.
            return;
        }
    }

    self->m_fwdOk++;
    ucb(route, p, header);
}

void
MaliciousRouting::ErrorHook(MaliciousRouting* self,
                            ErrorCallback ecb,
                            Ptr<const Packet> p,
                            const Ipv4Header& header,
                            Socket::SocketErrno err)
{
    // Invoked by AODV when a transit packet cannot be routed (no route /
    // broken route). Counted for every node (benign + malicious) so the
    // feature pipeline can separate "malicious drop" from "no-route drop".
    self->m_noRoute++;
    ecb(p, header, err);
}

bool
MaliciousRouting::RouteInput(Ptr<const Packet> p,
                             const Ipv4Header& header,
                             Ptr<const NetDevice> idev,
                             const UnicastForwardCallback& ucb,
                             const MulticastForwardCallback& mcb,
                             const LocalDeliverCallback& lcb,
                             const ErrorCallback& ecb)
{
    // Wrap both the unicast-forward and error callbacks so our counters fire
    // whether forwarding happens synchronously or after AODV finishes a
    // route discovery. Local delivery (lcb) and multicast (mcb) are passed
    // through untouched.
    UnicastForwardCallback wrappedUcb = MakeBoundCallback(&MaliciousRouting::ForwardHook, this, ucb);
    ErrorCallback wrappedEcb = MakeBoundCallback(&MaliciousRouting::ErrorHook, this, ecb);

    return aodv::RoutingProtocol::RouteInput(p, header, idev, wrappedUcb, mcb, lcb, wrappedEcb);
}

} // namespace ns3
