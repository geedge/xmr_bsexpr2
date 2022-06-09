local dumper = Dumper.new("one_pkt.pcap")

do
    local function packet_listener()
        local tap = Listener.new("frame", "tcp and (!tcp.analysis.retransmission) and !icmp and !icmpv6")
        -- frame是监听器的名称，tcp是wireshark过滤器规则

        function tap.reset()
            print("tap reset")
        end

        function tap.packet(pinfo, tvb)
            -- 回调函数，每收到一个包执行一次。
            
            if( tostring(pinfo.number) == "927003" ) then
                dumper:dump_current()
            end
        end

        function tap.draw()
            -- 结束执行

        end
    end
       -- 监听报文
    packet_listener()
       -- tcpStreamTable =nil
end