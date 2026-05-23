import socket
import struct
import os
import threading

BASE = '/home/cisco'
BLKSIZE = 512


def handle_request(data, addr, main_sock):
    opcode = struct.unpack('!H', data[:2])[0]
    if opcode != 1:
        return
    parts = data[2:].split(b'\x00')
    fname = parts[0].decode(errors='replace')
    path = os.path.join(BASE, os.path.basename(fname))
    print(f'RRQ {addr} -> {fname} -> {path}', flush=True)

    if not os.path.exists(path):
        err = struct.pack('!HH', 5, 1) + b'File not found\x00'
        main_sock.sendto(err, addr)
        print(f'NOT FOUND: {path}', flush=True)
        return

    # Send from a new socket bound to an ephemeral port
    # Use the SAME address the client sent to (standard TFTP)
    ts = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ts.settimeout(10)
    ts.bind(('0.0.0.0', 0))

    try:
        with open(path, 'rb') as f:
            blk = 1
            while True:
                chunk = f.read(BLKSIZE)
                pkt = struct.pack('!HH', 3, blk) + chunk
                sent = False
                for attempt in range(6):
                    ts.sendto(pkt, addr)
                    try:
                        ack, ack_addr = ts.recvfrom(4)
                        if len(ack) >= 4 and struct.unpack('!HH', ack[:4])[1] == blk:
                            sent = True
                            break
                    except socket.timeout:
                        print(f'  timeout waiting for ACK {blk}, retry {attempt+1}', flush=True)
                if not sent:
                    print(f'  gave up on block {blk}', flush=True)
                    break
                blk += 1
                if len(chunk) < BLKSIZE:
                    break
        print(f'  done sending {fname} ({blk-1} blocks)', flush=True)
    except Exception as e:
        print(f'  error: {e}', flush=True)
    finally:
        ts.close()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 69))
    sock.settimeout(300)
    print('TFTP ready on port 69', flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(516)
            t = threading.Thread(target=handle_request, args=(data, addr, sock), daemon=True)
            t.start()
        except socket.timeout:
            pass
        except Exception as e:
            print(f'main error: {e}', flush=True)


if __name__ == '__main__':
    main()
