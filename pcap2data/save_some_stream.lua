local dumper = Dumper.new("some_stream.pcap")
local getTcpStream = Field.new("tcp.stream")

do
    local function packet_listener()
        local tap = Listener.new("frame", "(ip.src_host == \"192.168.11.219\" and ip.dst_host == \"52.139.250.253\") or (ip.src_host == \"52.139.250.253\" and ip.dst_host == \"192.168.11.219\")")
        -- frame是监听器的名称，tcp是wireshark过滤器规则

        function tap.reset()
            print("tap reset")
        end

        function tap.packet(pinfo, tvb)
            -- 回调函数，每收到一个包执行一次。


            dumper:dump_current()
            
        end

        function tap.draw()
            -- 结束执行

        end
    end
       -- 监听报文
    packet_listener()
       -- tcpStreamTable =nil
end