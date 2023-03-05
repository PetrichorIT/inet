# 69.0.0.* server network

srv1.node[0] is a root dns server
srv1.node[1] is a top level dns server for "*.org"
srv1.node[2] is a top level dns server for "*.example.org"

srv1.node[3] is www.example.org // a server that will respond to simple tcp/udp requets
srv1.node[4] is streaming.example.org // a server only tcp long data stream

# 104.0.0.* client network

isp1.node[0] only makes dns requests with low frequency.
isp1.node[1] connects to isp1.node[2] with tcp and udp
isp1.node[2] anwsers isp.node[1]
isp1.node[3] connects to www.example.org
isp2.node[4] connects to both www.example.org and straming.example.org