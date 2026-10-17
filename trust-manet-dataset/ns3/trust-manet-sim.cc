/*
 * TRUST-MANET : trust-manet-sim.cc
 * --------------------------------
 * One parameterised ns-3 run of an AODV MANET under a chosen attack mode.
 * Produces three files per run:
 *
 *   <prefix>_nodes.csv : per-window, per-node measurements (deltas within the window)
 *   <prefix>_edges.csv : per-window 1-hop adjacency (node pairs within rangeM)
 *   <prefix>_meta.json : the run configuration + ground-truth malicious node IDs
 *
 * The Python pipeline (scripts/build_dataset.py) turns these into the
 * per-(observer, neighbour, window) Parquet dataset described in the proposal.
 *
 * Install: copy this file + malicious-routing.{h,cc} into
 *          <ns3>/scratch/trust-manet/  and build with
 *          ./ns3 build trust-manet
 *
 * Targeted ns-3 version: ns-3.42.
 */
#include "malicious-routing.h"

#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("TrustManetSim");

// ---------------------------------------------------------------------------
// Routing helper that installs MaliciousRouting (an AODV subclass) on every
// node. Maliciousness is switched on afterwards per selected node.
// ---------------------------------------------------------------------------
class MaliciousAodvHelper : public Ipv4RoutingHelper
{
  public:
    MaliciousAodvHelper() { m_factory.SetTypeId("ns3::MaliciousRouting"); }

    MaliciousAodvHelper* Copy() const override { return new MaliciousAodvHelper(*this); }

    Ptr<Ipv4RoutingProtocol> Create(Ptr<Node> node) const override
    {
        Ptr<MaliciousRouting> agent = m_factory.Create<MaliciousRouting>();
        node->AggregateObject(agent);
        return agent;
    }

  private:
    ObjectFactory m_factory;
};

// ---------------------------------------------------------------------------
// Application traffic counters (indexed by node id).
// ---------------------------------------------------------------------------
static void
TxSink(std::vector<uint64_t>* v, uint32_t node, Ptr<const Packet>)
{
    (*v)[node]++;
}

static void
RxSink(std::vector<uint64_t>* v, uint32_t node, Ptr<const Packet>, const Address&)
{
    (*v)[node]++;
}

// ---------------------------------------------------------------------------
// Per-window collector.
// ---------------------------------------------------------------------------
struct Collector
{
    NodeContainer nodes;
    uint32_t nNodes = 0;
    double windowSec = 5.0;
    double rangeM = 120.0;
    double simStop = 200.0;

    std::ofstream nodesOut;
    std::ofstream edgesOut;

    std::vector<uint64_t> pRecv, pOk, pDrop, pNoRoute, pTx, pRx; // previous cumulative
    std::vector<uint64_t>* appTx = nullptr;
    std::vector<uint64_t>* appRx = nullptr;

    uint32_t widx = 0;

    void Start()
    {
        pRecv.assign(nNodes, 0);
        pOk.assign(nNodes, 0);
        pDrop.assign(nNodes, 0);
        pNoRoute.assign(nNodes, 0);
        pTx.assign(nNodes, 0);
        pRx.assign(nNodes, 0);

        nodesOut << "window_idx,time_s,node,pos_x,pos_y,vel_x,vel_y,speed,"
                    "recv_forward,fwd_ok,fwd_drop_attack,no_route,app_tx,app_rx\n";
        edgesOut << "window_idx,i,j,dist\n";

        Simulator::Schedule(Seconds(windowSec), &Collector::Sample, this);
    }

    void Sample()
    {
        const double t = Simulator::Now().GetSeconds();
        std::vector<Vector> pos(nNodes);

        for (uint32_t n = 0; n < nNodes; ++n)
        {
            Ptr<Node> node = nodes.Get(n);
            Ptr<MobilityModel> mm = node->GetObject<MobilityModel>();
            Vector p = mm->GetPosition();
            Vector v = mm->GetVelocity();
            pos[n] = p;

            Ptr<MaliciousRouting> r = node->GetObject<MaliciousRouting>();

            const uint64_t recv = r->m_recvForward;
            const uint64_t ok = r->m_fwdOk;
            const uint64_t drop = r->m_fwdDropAttack;
            const uint64_t nr = r->m_noRoute;
            const uint64_t tx = (*appTx)[n];
            const uint64_t rx = (*appRx)[n];

            const uint64_t dRecv = recv - pRecv[n];
            const uint64_t dOk = ok - pOk[n];
            const uint64_t dDrop = drop - pDrop[n];
            const uint64_t dNr = nr - pNoRoute[n];
            const uint64_t dTx = tx - pTx[n];
            const uint64_t dRx = rx - pRx[n];

            const double speed = std::sqrt(v.x * v.x + v.y * v.y + v.z * v.z);

            nodesOut << widx << ',' << t << ',' << n << ',' << p.x << ',' << p.y << ',' << v.x
                     << ',' << v.y << ',' << speed << ',' << dRecv << ',' << dOk << ',' << dDrop
                     << ',' << dNr << ',' << dTx << ',' << dRx << '\n';

            pRecv[n] = recv;
            pOk[n] = ok;
            pDrop[n] = drop;
            pNoRoute[n] = nr;
            pTx[n] = tx;
            pRx[n] = rx;
        }

        // 1-hop adjacency within observation range.
        for (uint32_t i = 0; i < nNodes; ++i)
        {
            for (uint32_t j = i + 1; j < nNodes; ++j)
            {
                const double d = CalculateDistance(pos[i], pos[j]);
                if (d <= rangeM)
                {
                    edgesOut << widx << ',' << i << ',' << j << ',' << d << '\n';
                }
            }
        }

        widx++;
        if (Simulator::Now().GetSeconds() + windowSec <= simStop + 1e-9)
        {
            Simulator::Schedule(Seconds(windowSec), &Collector::Sample, this);
        }
    }
};

// ---------------------------------------------------------------------------
int
main(int argc, char* argv[])
{
    // ---- parameters ----
    uint32_t nNodes = 50;
    double speed = 5.0;             // m/s (0 => static)
    double compromisedFrac = 0.10;  // fraction of nodes that are attackers
    std::string attackType = "blackhole"; // clean | blackhole | grayhole
    double grayholeDropProb = 0.5;
    uint32_t nFlows = 15;
    double simTime = 200.0;
    double windowSec = 5.0;
    double attackStart = 20.0;
    double appStart = 2.0;
    double areaX = 1500.0;
    double areaY = 1500.0;
    double rangeM = 120.0;
    uint32_t seed = 1;
    std::string outPrefix = "run";

    CommandLine cmd(__FILE__);
    cmd.AddValue("nNodes", "Number of nodes", nNodes);
    cmd.AddValue("speed", "Max node speed in m/s (0 = static)", speed);
    cmd.AddValue("compromisedFrac", "Fraction of compromised nodes", compromisedFrac);
    cmd.AddValue("attackType", "clean | blackhole | grayhole", attackType);
    cmd.AddValue("grayholeDropProb", "Drop probability for grayhole", grayholeDropProb);
    cmd.AddValue("nFlows", "Number of CBR UDP flows", nFlows);
    cmd.AddValue("simTime", "Simulation time (s)", simTime);
    cmd.AddValue("windowSec", "Measurement window (s)", windowSec);
    cmd.AddValue("attackStart", "Attack start time (s)", attackStart);
    cmd.AddValue("appStart", "Application start time (s)", appStart);
    cmd.AddValue("areaX", "Area width (m)", areaX);
    cmd.AddValue("areaY", "Area height (m)", areaY);
    cmd.AddValue("rangeM", "Observation/adjacency range (m)", rangeM);
    cmd.AddValue("seed", "RNG run (also seeds node/flow selection)", seed);
    cmd.AddValue("outPrefix", "Output file prefix", outPrefix);
    cmd.Parse(argc, argv);

    SeedManager::SetSeed(1);
    SeedManager::SetRun(seed);

    // Deterministic (seed-controlled) selection independent of ns-3 streams.
    std::mt19937 gen(static_cast<uint32_t>(seed) * 2654435761u + 12345u);

    NodeContainer nodes;
    nodes.Create(nNodes);

    // ---- Wi-Fi (802.11b ad hoc) ----
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211b);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
                                 "DataMode",
                                 StringValue("DsssRate11Mbps"),
                                 "ControlMode",
                                 StringValue("DsssRate1Mbps"));

    YansWifiChannelHelper channel = YansWifiChannelHelper::Default();
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());

    WifiMacHelper mac;
    mac.SetType("ns3::AdhocWifiMac");

    NetDeviceContainer devices = wifi.Install(phy, mac, nodes);

    // ---- mobility ----
    MobilityHelper mob;
    Ptr<RandomRectanglePositionAllocator> posAlloc =
        CreateObject<RandomRectanglePositionAllocator>();
    {
        std::ostringstream sx, sy;
        sx << "ns3::UniformRandomVariable[Min=0|Max=" << areaX << "]";
        sy << "ns3::UniformRandomVariable[Min=0|Max=" << areaY << "]";
        posAlloc->SetAttribute("X", StringValue(sx.str()));
        posAlloc->SetAttribute("Y", StringValue(sy.str()));
    }
    mob.SetPositionAllocator(posAlloc);

    if (speed <= 0.0)
    {
        mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    }
    else
    {
        std::ostringstream sp;
        sp << "ns3::ConstantRandomVariable[Constant=" << speed << "]";
        mob.SetMobilityModel("ns3::RandomWaypointMobilityModel",
                             "Speed",
                             StringValue(sp.str()),
                             "Pause",
                             StringValue("ns3::ConstantRandomVariable[Constant=0.0]"),
                             "PositionAllocator",
                             PointerValue(posAlloc));
    }
    mob.Install(nodes);

    // ---- internet stack with malicious-capable AODV ----
    MaliciousAodvHelper malHelper;
    InternetStackHelper internet;
    internet.SetRoutingHelper(malHelper);
    internet.Install(nodes);

    Ipv4AddressHelper address;
    address.SetBase("10.1.0.0", "255.255.0.0"); // /16 supports up to ~65k hosts
    Ipv4InterfaceContainer ifaces = address.Assign(devices);

    // ---- choose malicious nodes ----
    std::vector<uint32_t> idx(nNodes);
    std::iota(idx.begin(), idx.end(), 0);
    std::shuffle(idx.begin(), idx.end(), gen);

    uint32_t nMal = 0;
    MaliciousRouting::AttackType atk = MaliciousRouting::NONE;
    if (attackType == "blackhole")
    {
        atk = MaliciousRouting::BLACKHOLE;
    }
    else if (attackType == "grayhole")
    {
        atk = MaliciousRouting::GRAYHOLE;
    }
    else
    {
        atk = MaliciousRouting::NONE; // "clean"
    }

    if (atk != MaliciousRouting::NONE)
    {
        nMal = static_cast<uint32_t>(std::floor(compromisedFrac * nNodes));
    }

    std::vector<uint32_t> malicious(idx.begin(), idx.begin() + nMal);
    std::sort(malicious.begin(), malicious.end());

    for (uint32_t m : malicious)
    {
        Ptr<MaliciousRouting> r = nodes.Get(m)->GetObject<MaliciousRouting>();
        r->SetAttack(atk, grayholeDropProb, Seconds(attackStart), Seconds(simTime));
    }

    // ---- traffic: nFlows random source->destination CBR UDP flows ----
    std::vector<uint64_t> appTx(nNodes, 0), appRx(nNodes, 0);
    std::uniform_int_distribution<uint32_t> pick(0, nNodes - 1);

    for (uint32_t f = 0; f < nFlows; ++f)
    {
        uint32_t src = pick(gen);
        uint32_t dst = pick(gen);
        while (dst == src)
        {
            dst = pick(gen);
        }
        uint16_t port = static_cast<uint16_t>(9000 + f);

        OnOffHelper onoff("ns3::UdpSocketFactory",
                          InetSocketAddress(ifaces.GetAddress(dst), port));
        onoff.SetAttribute("DataRate", StringValue("16kbps"));
        onoff.SetAttribute("PacketSize", UintegerValue(512));
        onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        ApplicationContainer srcApp = onoff.Install(nodes.Get(src));
        srcApp.Start(Seconds(appStart));
        srcApp.Stop(Seconds(simTime - 1.0));

        PacketSinkHelper sink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), port));
        ApplicationContainer sinkApp = sink.Install(nodes.Get(dst));
        sinkApp.Start(Seconds(1.0));
        sinkApp.Stop(Seconds(simTime));

        srcApp.Get(0)->TraceConnectWithoutContext("Tx", MakeBoundCallback(&TxSink, &appTx, src));
        sinkApp.Get(0)->TraceConnectWithoutContext("Rx", MakeBoundCallback(&RxSink, &appRx, dst));
    }

    // ---- collector ----
    Collector col;
    col.nodes = nodes;
    col.nNodes = nNodes;
    col.windowSec = windowSec;
    col.rangeM = rangeM;
    col.simStop = simTime;
    col.appTx = &appTx;
    col.appRx = &appRx;
    col.nodesOut.open(outPrefix + "_nodes.csv");
    col.edgesOut.open(outPrefix + "_edges.csv");
    col.Start();

    // ---- meta ----
    {
        std::ofstream meta(outPrefix + "_meta.json");
        meta << "{\n";
        meta << "  \"n_nodes\": " << nNodes << ",\n";
        meta << "  \"speed\": " << speed << ",\n";
        meta << "  \"compromised_frac\": " << compromisedFrac << ",\n";
        meta << "  \"attack_type\": \"" << attackType << "\",\n";
        meta << "  \"grayhole_drop_prob\": " << grayholeDropProb << ",\n";
        meta << "  \"n_flows\": " << nFlows << ",\n";
        meta << "  \"sim_time\": " << simTime << ",\n";
        meta << "  \"window_sec\": " << windowSec << ",\n";
        meta << "  \"attack_start\": " << attackStart << ",\n";
        meta << "  \"app_start\": " << appStart << ",\n";
        meta << "  \"area_x\": " << areaX << ",\n";
        meta << "  \"area_y\": " << areaY << ",\n";
        meta << "  \"range_m\": " << rangeM << ",\n";
        meta << "  \"seed\": " << seed << ",\n";
        meta << "  \"malicious_nodes\": [";
        for (size_t k = 0; k < malicious.size(); ++k)
        {
            meta << malicious[k] << (k + 1 < malicious.size() ? ", " : "");
        }
        meta << "]\n}\n";
    }

    Simulator::Stop(Seconds(simTime));
    Simulator::Run();
    Simulator::Destroy();

    col.nodesOut.close();
    col.edgesOut.close();
    return 0;
}
