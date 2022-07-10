import socket


def stor_callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    fuzz_data_logger.log_check("Each request(node) callback!")
    print(target)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('192.168.1.42 ', 50000))
    s.listen(5)
    fuzz_data_logger.log_check('Waiting for connection...')

    sock, addr = s.accept()
    #sock.send('Welcome!'.encode('utf-8'))
    fp = open('/home/haoyu-fuzzer/zhechang/boofuzz_test/test.py', 'rb')
    while True:
        data = fp.read(1024)
        if not data:
            print('END')
            break
        sock.send(data)
    sock.close()
    s.close()
    #target= Target(connection=TCPSocketConnection("172.16.39.141", 20))
    print(node)
    print(edge)
    print(session.last_recv)


def list_callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    fuzz_data_logger.log_check("Each request(node) callback!")
    print(target)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('192.168.1.42 ', 50000))
    s.listen(5)
    fuzz_data_logger.log_check('Waiting for connection...')

    sock, addr = s.accept()
    #sock.send('Welcome!'.encode('utf-8'))
    #fp = open('/home/haoyu-fuzzer/zhechang/boofuzz_test/test.py','rb')
    while True:
        data =sock.recv(1024)
        if not data:
            fuzz_data_logger.log_check('LIST...')
            fuzz_data_logger.log_check(data.decode('utf-8'))
            break
        #fuzz_data_logger.log_check(data.decode('utf-8'))
    sock.close()
    s.close()
