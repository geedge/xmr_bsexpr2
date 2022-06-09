-- print(_VERSION)
-- /usr/local/share/wireshark/init.lua
local json = require("cjson")
local md5 = require("md5")
require "bit32"
local cj = json.new()

local getTcpStream = Field.new("tcp.stream")

-- ip/tcp info
local tcpWs = Field.new("tcp.window_size")
local ipTtl = Field.new("ip.ttl")
local ipDf = Field.new( "ip.flags.df" )
local ipHdl = Field.new( "ip.hdr_len" )
local tcpHdl = Field.new( "tcp.hdr_len" )
local tcpOpts = Field.new("tcp.options")
local ipLen = Field.new("ip.len")
local ipId = Field.new("ip.id")
local ipVer = Field.new("ip.version")
local tcpSeq = Field.new("tcp.seq_raw")
local tcpAck = Field.new("tcp.ack_raw")
local tcpTSval = Field.new("tcp.options.timestamp.tsval")
local tcpTSecr = Field.new("tcp.options.timestamp.tsecr")

-- All TCP Flags
local tfStr = Field.new("tcp.flags.str")
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

local getTcpPayload = Field.new("tcp.len")

-- tls info
local tlsCerts = Field.new("tls.handshake.certificates")
local tlsSni = Field.new("tls.handshake.extensions_server_name")
local tlsCert = Field.new("tls.handshake.certificate")

-- tls info, for generate ja3
local tlsHandShakeType = Field.new("tls.handshake.type")
local tlsHandShakeVersion = Field.new("tls.handshake.version")
local tlsCipher = Field.new("tls.handshake.ciphersuite")
local tlsExtType = Field.new("tls.handshake.extension.type")
local tlsExtsg = Field.new("tls.handshake.extensions_supported_group")
local tlsExtec = Field.new("tls.handshake.extensions_ec_point_format")
-- 
local tlsNewST = Field.new("tls.handshake.session_ticket")
local tlsNewSTTime = Field.new("tls.handshake.session_ticket_lifetime_hint")

local flows = {}
local grease_table = {
    ["2570"] = true,
    ["6682"] = true,
    ["10794"] = true,
    ["14906"] = true,
    ["19018"] = true,
    ["23130"] = true,
    ["27242"] = true,
    ["31354"] = true,
    ["35466"] = true,
    ["39578"] = true,
    ["43690"] = true,
    ["47802"] = true,
    ["51914"] = true,
    ["56026"] = true,
    ["60138"] = true,
    ["64250"] = true
}

local function getTcpFp(opt, tcpflags)

    -- print( pinfo.number )

    local tcp_opt_table = { [0] = "E", -- eol
        [1] = "N", -- nop
        [2] = "M", -- mss
        [3] = "W", -- ws
        [4] = "S", -- sack
        [5] = "K", -- sack_param
        [6] = "J",
        [7] = "F",
        [8] = "T", -- time
        [9] = "P",
        [10] = "R"
        -- ["22"] = "tfo"      -- tcp fast open
    }

    -- TCP fingerprint's format be like: 65535:64:1:60:M1460,S,T,N,W8:.
    local tcp_fp = tostring( tcpWs() )..":"
    tcp_fp = tcp_fp..tostring( ipTtl() )..":"
    tcp_fp = tcp_fp..tostring( bit32.rshift( bit32.band( ipDf().range:uint(), 0x4000 ), 14) )..":"

    local ip_hdl = bit32.band( ipHdl().range:uint(), 0x0F) * 4
    local tcp_hdl = bit32.rshift( bit32.band( tcpHdl().range:uint(), 0xF0), 4 ) * 4
    tcp_fp = tcp_fp..tostring( ip_hdl + tcp_hdl )..":"

    local opts_byte = opt.range
    local opts_size = opt.range:len()
    local opts_str = ""
    local cur = 0

    while ( cur < opts_size ) do
        local opt_type = opts_byte:range( cur, 1 ):uint()

        if ( opt_type == 0 ) then -- eol
            opts_str = opts_str.."E,"
            break
        end
        
        local opt_size = 0
        if( cur + 1< opts_size ) then -- tcp options 的最后一个可能是 eol 也可能是 nop
            opt_size = opts_byte:range( cur + 1, 1 ):uint()
        end

        if( tcp_opt_table[opt_type] == nil ) then 
            opts_str = opts_str.."U," -- unknown
            cur = cur + opt_size
        else
            opts_str = opts_str..tcp_opt_table[opt_type]
            if ( opt_type == 2 or opt_type == 3) then
                opts_str = opts_str..tostring( opts_byte:range( cur + 2, opt_size - 2):uint() )
                cur = cur + opt_size
            elseif ( opt_type == 1 ) then
                cur = cur + 1
            else
                cur = cur + opt_size
            end
            opts_str = opts_str..","
        end
    end

    tcp_fp = tcp_fp..string.sub( opts_str, 1, -2 )..":"

    local odd = ""

    if ( string.sub( opts_str, -1, -1 ) == "E" ) then
        odd = odd.."p"
    end

    if ( ipId().range:uint() == 0 ) then
        odd = odd.."Z" -- 65535:64:1:64:M1460,N,W6,N,N,T,S,E:Z
    end

    if ( ip_hdl > 20 ) then
        odd = odd.."I"
    end

    local x_len = 0
    if ( bit32.rshift( bit32.band( ipVer().range:uint(), 0x40), 4) == 4 ) then
        x_len = ipLen().range:uint() - ip_hdl - tcp_hdl
    end

    if ( x_len > 0 ) then
        odd = odd.."D"
    end

    if ( string.sub( tcpflags, 1, 1 ) == "U" ) then
        odd = odd.."U"
    end

    if ( ( tcpflags == "....S." or tcpflags == ".A..S." ) and tcpAck().range:uint() ~= 0 ) then
        odd = odd.."A"
    end

    if ( tcpTSecr() ~= nil ) then
        if ( tcpflags == "....S." and tcpTSecr().range:uint() ~= 0 ) then
            odd = odd.."T"
        end
    end

    if ( odd == "" ) then
        odd = "."
    end

    tcp_fp = tcp_fp..odd

    -- print( tcp_fp )
    return tcp_fp
end

local function get_tls12_info(flows, tcp_stream)
    if( tlsHandShakeType() ~= nil ) then
        -- tls.handshake.type == 1 为 Client Hello 报文, 
        -- 提取 ja3 指纹， 客户端发出的 session ticket
        local tlshstype = tostring(tlsHandShakeType())

        if ( tlshstype == "1" ) then
            if ( tlsSni() ~= nil ) then flows[tcp_stream].sni = tostring( tlsSni() ) end
            -- tls.handshake.version
            local tlshsv = tostring( tonumber( tostring(tlsHandShakeVersion()) ) ) -- 不能是 tostring(tlsHandShakeVersion()) ！！！

            local cipher_str = ""                
            if( tlsCipher() ) then
                local ciphers = { tlsCipher() }
                for _, cipher in ipairs( ciphers ) do
                    cipher = tostring(cipher)
                    if( not grease_table[cipher] ) then
                        if cipher_str ~= "" then
                            cipher_str = cipher_str.."-"..cipher
                        else
                            cipher_str = cipher
                        end
                    end
                end
            end

            local ext_str = ""
            if( tlsExtType() ) then
                local exts = { tlsExtType() }
                local ext_tvb
                for _, ext in ipairs( exts ) do
                    -- 提取Client Hello 中的 tls session Ticket
                    local s_t = "EMPTY"
                    ext_tvb = ext.source
                    if( tostring(ext) == "35" ) then
                        local ofs = ext.offset
                        local s_t_len = ext_tvb:range(ofs + 2, 2):uint()
                        if( tonumber(s_t_len) ~= 0 ) then
                            s_t = ext_tvb:range(ofs + 4, tonumber(s_t_len)):bytes():tohex()
                        end
                        flows[tcp_stream].s_t = s_t
                    end

                    ext = tostring(ext)
                    if( not grease_table[ext] ) then
                        if ext_str ~= "" then
                            ext_str = ext_str.."-"..ext
                        else
                            ext_str = ext
                        end
                    end
                end
            end
            
            local sg_str = ""
            if( tlsExtsg() ) then
                local sgs = { tlsExtsg() }
                for _, sg in ipairs( sgs ) do
                    sg = tostring( tonumber( tostring( sg ) ) )
                    if( not grease_table[sg] ) then
                        if sg_str ~= "" then
                            sg_str = sg_str.."-"..sg
                        else
                            sg_str = sg
                        end
                    end
                end
            end

            local ec_str = ""
            if( tlsExtec() ) then
                local ecs = { tlsExtec() }
                for _, ec in ipairs( ecs ) do
                    ec = tostring(ec)
                    if ec_str ~= "" then
                        ec_str = ec_str.."-"..ec
                    else
                        ec_str = ec
                    end
                end
            end

            -- lows[tcp_stream].ja3 = tlshsv..","..cipher_str..","..ext_str..","..sg_str..","..ec_str
            local ja3 = tlshsv..","..cipher_str..","..ext_str..","..sg_str..","..ec_str
            flows[tcp_stream].ja3_md5 = md5.sumhexa( ja3 )
        
        -- tls.handshake.type == 4 为 New Session Ticket 报文
        -- 提取服务端发出的 session ticket
        elseif( tlshstype == "4" ) then
            flows[tcp_stream].ser_s_t = tlsNewST().range:bytes():tohex()
            flows[tcp_stream].ser_s_t_t = tlsNewSTTime().range:uint()
        end
    end
end

local function get_cert_info(pinfo, flows, tcp_stream, direction)
    -- tls.handshake.type == 11 为证书
    if( tlsCerts() ~= nil ) then
        -- 提取证书信息，证书的编码形式为 ASN.1(T-L-V)，详细可见: https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/

        -- 输入一个 字节串 对象，pos 是字节串对象中下一个要处理的字节的位置
        -- 得到 ASN.1 对象数据类型：type；得到 ASN.1 数据长度；得到 ASN.1 数据在 TvbRange 中的开始位置
        local function get_item_len(tvbRange, pos)
            local type = tvbRange:range(pos, 1):uint()
            pos = pos + 1
            local len = tvbRange:range(pos, 1):uint()
            pos = pos + 1
            if( bit32.band(len, 0x80) == 0x80 ) then
                local to_read = bit32.band(len, 0x7F)
                len = tvbRange:range(pos, to_read):uint()
                pos = pos + to_read
            end
            return len, pos
        end

        -- 得到证书中的 id-at-organizationName
        local function get_cert_item_info(cert)
            local id_at_organizationName = ""
            -- cert 头部
            local len, pos = get_item_len(cert, 0)

            -- x509af.signedCertificate_element
            len, pos = get_item_len(cert, pos)

            -- x509af.version or x509af.serialNumber
            len, pos = get_item_len(cert, pos)
            local value = cert:range(pos, len):bytes():tohex()
            pos = pos + len
            if ( value == "020102" ) then
                local x509af_version = "v3"
                len, pos = get_item_len(cert, pos)
                local x509af_serialNumber = cert:range(pos, len):bytes():tohex()
                pos = pos + len
            else
                -- 证书可能不带版本号
                local x509af_serialNumber = value
            end

            -- signature
            len, pos = get_item_len(cert, pos)
            local value = cert:range(pos, len):bytes():tohex()
            pos = pos + len

            -- issuer
            len, pos = get_item_len(cert, pos)
            local value = cert:range(pos, len):bytes():tohex()
            pos = pos + len

            -- validity
            len, pos = get_item_len(cert, pos)
            -- local value = cert:range(pos, len):bytes():tohex()
            pos = pos + len

            -- subjects
            len, pos = get_item_len(cert, pos)
            -- subjects 在 ASN.1 中是一个序列（30），其中有多个元素，每个元素是 RdnSequence，循环处理
            local subjects_max_pos = pos + len
            while( pos < subjects_max_pos ) do
                -- RdnSequence 在 ASN.1 中是一个集合（31），每个元素是 RDN， 循环处理
                len, pos = get_item_len(cert, pos)
                local rdnreq_max_pos = pos + len
                while( pos < rdnreq_max_pos ) do
                    -- RDN 元素是一个集合，同样需要处理
                    len, pos = get_item_len(cert, pos)
                    local rdn_max_pos = pos + len
                    while( pos < rdn_max_pos ) do
                        -- 读取 RDN 元素的 ID：
                        len, pos = get_item_len(cert, pos)
                        local rdn_id = cert:range(pos, len):bytes():tohex()
                        pos = pos + len

                        -- 读取 RDN 元素的值：
                        len, pos = get_item_len(cert, pos)
                        -- 存储 id-at-organizationName 类型 RDN 元素的值
                        if ( rdn_id == "55040A" ) then
                            id_at_organizationName = cert:range(pos, len):string(0x00000002) -- ENC_UTF_8
                        end
                        pos = pos + len
                    end
                end
            end
            return id_at_organizationName
        end

        -- 证书链上有多个证书，只需从最后一个证书提取信息即可
        local cert = tlsCert().range -- type: TvbRange

        if( direction == "s") then
            flows[tcp_stream].org = get_cert_item_info(cert)
        else
            flows[tcp_stream].client = get_cert_item_info(cert)
        end
    end
end

local function handle_tcp(pinfo)
    -- 回调函数，每收到一个包执行一次
    local src_ip = tostring(pinfo.net_src)
    local dst_ip = tostring(pinfo.net_dst)

    -- 不处理源、目的IP的都为 192.168.xx.xx 的 TCP 流，也就是内网通信的 TCP 流
    local env_ip_prefix = "192.168."
    if( string.find(src_ip, env_ip_prefix) and string.find(dst_ip, env_ip_prefix) ) then
        return 
    end

    local tcp_stream = tonumber( tostring( getTcpStream() ) )
    local tcp_payload = tostring( getTcpPayload() )
    local abs_ts = tostring( pinfo.abs_ts )
    
    local tcpflags = ""
    if( tostring(tfUrg()) == "1" ) then tcpflags = tcpflags.."U" else tcpflags = tcpflags.."." end
    if( tostring(tfAck()) == "1" ) then tcpflags = tcpflags.."A" else tcpflags = tcpflags.."." end
    if( tostring(tfPush()) == "1" ) then tcpflags = tcpflags.."P" else tcpflags = tcpflags.."." end
    if( tostring(tfReset()) == "1" ) then tcpflags = tcpflags.."R" else tcpflags = tcpflags.."." end
    if( tostring(tfSyn()) == "1" ) then tcpflags = tcpflags.."S" else tcpflags = tcpflags.."." end
    if( tostring(tfFin()) == "1" ) then tcpflags = tcpflags.."F" else tcpflags = tcpflags.."." end
    local direction = ""

    if( not flows[tcp_stream] ) then
        -- 建立一个字典，存储一个 TCP 流的信息和所有数据包
        flows[tcp_stream] = {}
        flows[tcp_stream].pkts = {}
        -- 流的第一个报文不一定是 SYN 报文，因为可能没捕获到流的开始
        if ( tcpflags == "....S." ) then
            flows[tcp_stream].src_ip = src_ip
            flows[tcp_stream].src_port = tonumber(pinfo.src_port)
            flows[tcp_stream].dst_ip = dst_ip
            flows[tcp_stream].dst_port = tonumber(pinfo.dst_port)
            flows[tcp_stream].tcp_fp = getTcpFp( tcpOpts(), tcpflags )
            direction = "c"
        else
            -- 若流的第一个报文不是 SYN 报文，要判断这个报文的方向
            if( string.find(src_ip, env_ip_prefix) ) then
                flows[tcp_stream].src_ip = src_ip
                flows[tcp_stream].dst_ip = dst_ip
                flows[tcp_stream].src_port = tonumber(pinfo.src_port)
                flows[tcp_stream].dst_port = tonumber(pinfo.dst_port)
                direction = "c"
            else
                flows[tcp_stream].src_ip = dst_ip
                flows[tcp_stream].dst_ip = src_ip
                flows[tcp_stream].src_port = tonumber(pinfo.dst_port)
                flows[tcp_stream].dst_port = tonumber(pinfo.src_port)
                direction = "s"
            end
        end
    else
        if ( tostring(pinfo.net_src) == flows[tcp_stream].src_ip )
        then
            direction = "c"
        else
            direction = "s"
        end
    end

    local pkt_info = abs_ts.." "..direction.." "..tcp_payload.." "..tcpflags.." "..tostring(tcpSeq().range:uint()).." "..tostring(tcpAck().range:uint())
    if ( tcpTSval() ~= nil ) then
       pkt_info = pkt_info.." "..tostring(tcpTSval().range:uint()).." "..tostring(tcpTSecr().range:uint())
    end
    table.insert(flows[tcp_stream].pkts, pkt_info)

    get_tls12_info(flows, tcp_stream)

    get_cert_info(pinfo, flows, tcp_stream, direction)

end

-- 处理数据包的主循环
do
    local function packet_listener()
        -- local tap = Listener.new("frame", "tcp and (!tcp.analysis.retransmission) and !icmp and !icmpv6", false)
        -- 这里不需要排除重传的 tcp 报文
        -- tcp udp icmp 
        local tap = Listener.new("frame", "tcp and !icmp and !icmpv6", false)
        -- oicq.command == 2 可见 QQ 号
        -- frame是监听器的名称，tcp是wireshark过滤器规则

        function tap.reset()
            -- 开始执行
            -- for x,y in ipairs(Field.list()) do
            --     print(y)
            -- end
        end

        function tap.packet(pinfo, tvb)
            handle_tcp(pinfo)
        end

        -- tls: org,sni*,
        -- http: ua,host,ref
        function tap.draw()
            -- 结束执行
            local cnt = 0
            local useful = 0
            -- for k, v in pairs(flows) do
            --     cnt = cnt + 1
            --     if( flows[k].sni ~= nil ) then
            --         if( flows[k].ja3_md5 ~= nil ) then
            --             if( flows[k].s_t ~= nil ) then
            --                 print( cj.encode(flows[k]) )
            --                 useful = useful + 1
            --             end
            --         end
            --     end
            -- end

            for k, v in pairs(flows) do
                flows[k].tcp_stream_id = k
                print( cj.encode(flows[k]) )
            end

            -- print( cnt )
            -- print( useful )

        end
    end

    packet_listener()

end