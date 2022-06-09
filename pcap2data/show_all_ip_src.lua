-- print(_VERSION)
-- /usr/local/share/wireshark/init.lua

local getTcpStream = Field.new("tcp.stream")

-- TCP新增的 tcp flags
local tfCwr = Field.new("tcp.flags.cwr")
local tfEcn = Field.new("tcp.flags.ecn")
-- TCP原本的 tcp flags
local tfUrg = Field.new("tcp.flags.urg")
local tfAck = Field.new("tcp.flags.ack")
local tfPush = Field.new("tcp.flags.push")
local tfReset = Field.new("tcp.flags.reset")
local tfSyn = Field.new("tcp.flags.syn")
local tfFin = Field.new("tcp.flags.fin")

local flows = {}
local ip_src = {}

local stream_first_pkt_is_not_syn = {}

local syn_pkt_is_not_first_pkt_of_stream_cnt = {}

local first_pkt_of_stream_is_syn = 0
local first_pkt_of_stream_is_not_syn = 0

local env_ip_prefix1 = "192.168."
local env_ip_prefix2 = "192.168."

do
    local function packet_listener()
        local tap = Listener.new("frame", "tcp and (!tcp.analysis.retransmission) and !icmp and !icmpv6")
        -- oicq.command == 2 可见 QQ 号
        -- frame是监听器的名称，tcp是 tshark 过滤器规则

        function tap.reset()
            -- 开始执行
        end

        function tap.packet(pinfo, tvb)
            -- 回调函数，每收到一个包执行一次。

            local src_ip = tostring(pinfo.net_src)
            local dst_ip = tostring(pinfo.net_dst)

            -- print(string.find(src_ip, env_ip_prefix1))
            -- print(string.find(src_ip, env_ip_prefix2))
            -- print(string.find(dst_ip, env_ip_prefix1))
            -- print(string.find(dst_ip, env_ip_prefix2))

            -- print( string.find(src_ip, env_ip_prefix1) or string.find(src_ip, env_ip_prefix2) )
            -- print( string.find(dst_ip, env_ip_prefix1) or string.find(dst_ip, env_ip_prefix2) )

            if ( (string.find(src_ip, env_ip_prefix1) or string.find(src_ip, env_ip_prefix2)) and (string.find(dst_ip, env_ip_prefix1) or string.find(dst_ip, env_ip_prefix2)) ) then
                return 
            end

            local tcp_stream = tonumber( tostring( getTcpStream() ) )
            local pkt_num = tonumber( tostring( pinfo.number ) )
            
            local tcpflags = ""
            if( tostring(tfUrg()) == "1") then tcpflags = tcpflags.."U" else tcpflags = tcpflags.."." end
            if( tostring(tfAck()) == "1" ) then tcpflags = tcpflags.."A" else tcpflags = tcpflags.."." end
            if( tostring(tfPush()) == "1" ) then tcpflags = tcpflags.."P" else tcpflags = tcpflags.."." end
            if( tostring(tfReset()) == "1" ) then tcpflags = tcpflags.."R" else tcpflags = tcpflags.."." end
            if( tostring(tfSyn()) == "1" ) then tcpflags = tcpflags.."S" else tcpflags = tcpflags.."." end
            if( tostring(tfFin()) == "1" ) then tcpflags = tcpflags.."F" else tcpflags = tcpflags.."." end
            local direction = ""

            -- SYN报文，非流的第一个包
            if( flows[tcp_stream] ) then
                if( tcpflags == "....S." ) then
                    syn_pkt_is_not_first_pkt_of_stream_cnt[pkt_num] = 1
                end
            end

            -- 包是流的第一个包
            if( not flows[tcp_stream] )
            then
                -- 流的第一个报文不一定是 SYN 报文，因为可能没捕获到流的开始
                if ( tcpflags == "....S." ) then
                    flows[tcp_stream] = {}

                    direction = "c"

                    ip = tostring(pinfo.net_src)

                    if( not ip_src[ip] ) then
                        ip_src[ip] = 1
                    else 
                        ip_src[ip] = ip_src[ip] + 1
                    end

                    first_pkt_of_stream_is_syn = first_pkt_of_stream_is_syn + 1
                else
                    flows[tcp_stream] = {}
                    stream_first_pkt_is_not_syn[pkt_num] = 1
                    first_pkt_of_stream_is_not_syn = first_pkt_of_stream_is_not_syn + 1
                end

            end

        end

        -- tls: org,sni*,
        -- http: ua,host,ref
        function tap.draw()
            -- 结束执行

            print("first_pkt_of_stream_is_syn")
            print(first_pkt_of_stream_is_syn)
            print("first_pkt_of_stream_is_not_syn")
            print(first_pkt_of_stream_is_not_syn)

            print("\n")

            print("syn_pkt_is_not_first_pkt_of_stream_cnt")
            for k, v in pairs(syn_pkt_is_not_first_pkt_of_stream_cnt) do
                print(k)
            end

            print("\n")

            print("stream_first_pkt_is_not_syn")
            for k, v in pairs(stream_first_pkt_is_not_syn) do
                print(k)
            end

            print("\n")

            for k, v in pairs(ip_src) do
                print(k)
            end
            
        end
    end
       -- 监听报文
    packet_listener()
       -- tcpStreamTable =nil
end
