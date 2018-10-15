import network_3_0
import argparse
from time import sleep
import time
import hashlib


class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)


    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S


    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]

        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S


class RDT:
    ## latest sequence number used in a packet
    seq_num = 0
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = network_3_0.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

    def rdt_3_0_send(self, msg_S):
        packet = Packet(self.seq_num, msg_S)
        timeout = 3
        holding_sequence = self.seq_num

        while holding_sequence == self.seq_num:
            self.network.udt_send(packet.get_byte_S())
            print('Packet sent in RDT 3 with message = ' + msg_S + '\n')
            receive_packet = ''

            timeout_start = time.time()
            timeout_end = time.time()
            while receive_packet == '' and timeout_end - timeout_start < timeout:
                receive_packet = self.network.udt_receive()
                timeout_end = time.time()

            if receive_packet == '':
                print('***Timeout***')
                continue

            length = int(receive_packet[:Packet.length_S_length])
            self.byte_buffer = receive_packet[length:]
            print('BUFFER UPDATED AND LENGTH ADDED IN SENDER\n')

            if Packet.corrupt(receive_packet[0:length]):
                print('Corrupted ACK in Sender\n')
                self.byte_buffer = ''
            else:
                response_packet = Packet.from_byte_S(receive_packet[0:length])
                print('PACKET RECEIVED WITH MESSAGE = ' + response_packet.msg_S + '\n')
                print('PACK SEQUENCE NUMBER = ' + str(response_packet.seq_num) + '\n')
                print('SEQUENCE NUMBER EXPECTED = ' + str(self.seq_num) + '\n')
                if response_packet.seq_num != self.seq_num:
                    print('Receiving retransmitted data')
                    ack = Packet(response_packet.seq_num, '1')
                    self.network.udt_send(ack.get_byte_S())
                elif response_packet.msg_S == '1':
                    print('ACK RECEIVED')
                    self.seq_num = 1 - self.seq_num
                    print('Sequence number in Sender updated to ' + str(self.seq_num) + '\n')
                elif response_packet.msg_S == '0':
                    print('NAK Received\n')
                    self.byte_buffer = ''
                    print('Byte Buffer updated in Sender\n')

    def rdt_3_0_receive(self):
        ret_S = None
        received_packet = self.network.udt_receive()
        #print('PACKET IN 3 RECEIVER RECEIVED\n')
        self.byte_buffer += received_packet
        holding_sequence = self.seq_num

        while holding_sequence == self.seq_num:

            if(len(self.byte_buffer) < Packet.length_S_length):
                #print('Return message 1...\n')
                return ret_S

            length = int(self.byte_buffer[:Packet.length_S_length])
            if len(self.byte_buffer) < length:
                print('Return message 2...\n')
                return ret_S

            if Packet.corrupt(self.byte_buffer):
                print('Packet corrupted in Receiver\n')
                nak = Packet(self.seq_num, '0')
                self.network.udt_send(nak.get_byte_S())
                print('Sent NAK Back\n')

            else:
                response = Packet.from_byte_S(self.byte_buffer[0:length])
                print('Received Packet Message = ' + response.msg_S + '\n')

                if (response.msg_S == '1' or response.msg_S == '0'):
                    print('Receiver received an ACK or NAK')
                    self.byte_buffer = self.byte_buffer[length:]
                    continue

                if response.seq_num != self.seq_num:
                    ack = Packet(response.seq_num, '1')
                    self.network.udt_send(ack.get_byte_S())

                elif response.seq_num == self.seq_num:
                    print('Received Packet sequence number = ' + str(response.seq_num) + '\n')
                    ack = Packet(self.seq_num, '1')
                    self.network.udt_send(ack.get_byte_S())
                    print('ACK sent back in 3 Receiver')
                    self.seq_num = 1 - self.seq_num
                    print('Sequence number in Receiver updated to ' + str(self.seq_num) + '\n')
                ret_S = response.msg_S if (ret_S is None) else ret_S + response.msg_S
                print('Return Message set to ' + ret_S + '\n')
            self.byte_buffer = self.byte_buffer[length:]
            print('Byte Buffer Updated in 3 Receiver\n')
        return ret_S



if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_3_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_3_0_receive())
        rdt.disconnect()


    else:
        sleep(1)
        print(rdt.rdt_3_0_receive())
        rdt.rdt_3_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
