# _x = FLOW("192.168.11.174", 56765, "218.11.11.221", 443)
# _y = FLOW("192.168.11.174", 56406, "218.11.11.221", 80)

# hash(c_ip) ^ hash(c_port) ^ hash(s_ip) ^ hash(s_port) 会哈希碰撞！！！
# print(_x.hash_code)
# print(_y.hash_code)

class FLOW: # 四元组
    def __init__(self, c_ip: str, c_port: str, s_ip: str, s_port: str):
        self.c_ip = c_ip
        self.c_port = c_port
        self.s_ip = s_ip
        self.s_port = s_port

        self.hash_code = hash(c_ip + str(c_port) + s_ip + str(s_port))

    def __hash__(self):
        return self.hash_code
        
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__hash__() == other.__hash__()
        else:
            return False

class TLS:
    """
    ja3指纹，SNI，一个或多个服务端IP
    可以表示一个单独的TLS客户端
    SNI可以对应服务端IP，他们之间可能共享ticket，也可能不共享，还可能部分共享
    用tc表示Tls_Client
    """
    def __init__(self, ja3: str, sni: str, server_ip: str, server_port: str):
        self.ja3 = ja3
        self.sni = sni
        self.server_ip = server_ip
        self.server_port = server_port
        self.hash_code = hash(self.ja3 + self.sni + self.server_ip + self.server_port)

    def __hash__(self):
        return self.hash_code

    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self.__hash__() == other.__hash__()
        else:
            return False

    def __repr__(self):
        return self.sni + ' ' + self.server_ip + ' ' + self.ja3

class PKT:
    def __init__(self, time: float, ndir: int, size: int, flag: int, s_t: int, flow: int, client_ip: str):
        self.time = time
        self.ndir = ndir
        self.size = size
        self.flag = flag
        self.s_t = s_t
        self.flow = flow
        self.client_ip = client_ip

class Feature:
    def __init__(self, time: float, ndir: int, size: int, flag: int, s_t: int, flow: int):
        self.time = time
        self.ndir = ndir
        self.size = size
        self.flag = flag
        self.s_t = s_t
        self.flow = flow
    
    def __str__(self):
        return "(" + str(self.time) + "," + str(self.ndir) + "," + str(self.size) + "," \
             + str(self.flag) + "," + str(self.s_t) + "," + str(self.flow) + ")"
        