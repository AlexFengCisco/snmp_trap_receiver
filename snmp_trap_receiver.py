'''
   SNMP trap receiver , for test NX OS snmp trap v1 v2c and deep understanding how snmp trap works

   Find decode detail in decode_description.txt
   
'''


import socket, struct

from socket import inet_ntoa



def print_snmp_trap(position,key,value):
    # TODO snmp print
    '''
       print content accodring to trap bytes postion and OID 
    '''
    position_skip = 0
    global snmp_ver
    global positon_bias

    #print(position)
    #print(positon_bias)

    if position == 3 or position == 2: # in case of len occupied two bytes
        print(key+' '+str(value)+ ' [snmp version '+snmp_ver+']')
    else:
        if snmp_ver == 'v2c':
            if position == 15+positon_bias:
                print(key + ' ' + str(value) + ' [snmp request ID]')
                position_skip = 1
            if position == 21+positon_bias:
                print(key + ' ' + str(value) + ' [error status]')
                position_skip = 1
            if position == 24+positon_bias:
                print(key + ' ' + str(value) + ' [error index]')
                position_skip = 1

        if snmp_ver == 'v1':
            pass

        if key == 'OS IP ADDR':
            ip_add = ''
            for net_seg in value:
                ip_add = ip_add+'.'+str(net_seg)
            ip_add = ip_add[1:]
            print(key+' '+ip_add+' [snmp v1 bind ip address]')
            position_skip = 1

        if key == 'OID':
            if value == '1.3.6.1.4.1.9.9.43.2':
                print(key+' '+str(value)+' [ciscoConfigManMIBNotificationPrefix]')
                position_skip = 1
            if value == '1.3.6.1.4.1.9.9.43.1.1.1.0':
                print(key+' '+str(value)+' [ccmHistoryRunningLastChanged]')
                position_skip = 1
            if value == '1.3.6.1.2.1.1.3.0':
                print(key + ' ' + str(value) + ' [sysUPtime]')
                position_skip = 1
            if value == '1.3.6.1.4.1.9.9.43.2.0.2':
                print(key + ' ' + str(value) + ' [ccmCLIRunningConfigChanged]')
                position_skip = 1
            if value == '1.3.6.1.6.3.1.1.4.1.0':
                print(key + ' ' + str(value) + ' [snmpTrapOID]')
                position_skip = 1
            '''
               check OID from support list , and make printable as sample.
            '''

        if position_skip == 0:
            print(key+' '+str(value))

    return

def parse_snmp_trap(snmp_trap_content):

    global snmp_ver
    global positon_bias

    snmp_trap_content_len = snmp_trap_content[1]
    if snmp_trap_content_len == 129:
        snmp_trap_content_len = snmp_trap_content[2]

    i = 0
    while True:
        hit = 0
        # print(snmp_trap_content[i])

        if i >= snmp_trap_content_len:
            break
        while snmp_trap_content[i] == 48: #0x30
            hit = 1
            # print('Sequence list  '+str(i))
            list_index = i
            list_len = snmp_trap_content[i + 1]
            if list_len == 129: #0x81
                list_len = snmp_trap_content[i + 2]
                if i == 0:
                    positon_bias += 1

                    if buf[5] == 0:
                        snmp_ver = 'v1'
                    if buf[5] == 1:
                        snmp_ver = 'v2c'
                i = i+2+1    
                #print('Snmp Trap Content List len ' + str(list_len))
            else:
                if i == 0:

                    if buf[4] == 0:
                        snmp_ver = 'v1'
                    if buf[4] == 1:
                        snmp_ver = 'v2c'
                i = i + 2
            break
            
        if i >= snmp_trap_content_len:
            break
        while snmp_trap_content[i] == 167: #0xa7
            hit = 1
            trap_len = snmp_trap_content[i+1]
            if trap_len == 129:
                positon_bias += 1

                trap_len = snmp_trap_content[i+2]
                i = i+2+1
            else:
                i = i+2
            break

        if i >= snmp_trap_content_len:
            break
        while snmp_trap_content[i] == 4: #0x04
            hit = 1
            key = 'OCT STRING'
            comm_str_len = snmp_trap_content[i+1]
            comm_str = snmp_trap_content[i+2:i+2+comm_str_len]
            print_snmp_trap(i,key,comm_str)
            #print('OCT STRING '+str(comm_str))
            i = i+2+comm_str_len
            break

        if i >= snmp_trap_content_len:
            break
        while snmp_trap_content[i] == 64: #0x40
            hit = 1
            key = 'OS IP ADDR'
            comm_str_len = snmp_trap_content[i+1]
            comm_str = snmp_trap_content[i+2:i+2+comm_str_len]
            print_snmp_trap(i,key,comm_str)
            #print('OCT STRING IP ADDR '+str(comm_str))
            i = i+2+comm_str_len
            break

        if i >= snmp_trap_content_len:
            break
        while snmp_trap_content[i] == 6: #0x06
            hit = 1
            key = 'OID'
            object_index = i
            # print('object identifier '+str(snmp_trap_content[i]))
            object_len = snmp_trap_content[i + 1]
            # print('object len '+str(object_len))
            OID_num = snmp_trap_content[object_index + 2:object_index + 2 + object_len]
            # print('OID '+str(snmp_trap_content[object_index+2:object_index+2+object_len]))
            OID_str = []
            for OID_i in OID_num:
                OID_str.append('.' + str(OID_i))

            if OID_str[0] == '.43':  # 43 = 1x40+3 snmp oid encode rule for first 2
                OID_str[0] = '1.3'
            OID = ''.join(map(str, (OID_str)))
            print_snmp_trap(i,key,OID)
            #print('OID '+OID)
            i = i + 2 + object_len
            break

        if i >= snmp_trap_content_len:
            break
        while snmp_trap_content[i] == 67: #0x43
            hit = 1
            time_tickt_index = i
            time_tickt_len = snmp_trap_content[i + 1]
            time_tickt_num = int(snmp_trap_content[time_tickt_index + 2:time_tickt_index + 2 + time_tickt_len].hex(),
                                 16)
            print('TIME Tickt ' + str(time_tickt_num))
            i = i + 2 + time_tickt_len
            break

        if i >= snmp_trap_content_len:
            break
        while snmp_trap_content[i] == 2: #0x02
            hit = 1
            key = 'INTEGER'
            int_index = i
            int_len = snmp_trap_content[i + 1]
            int_num = int(snmp_trap_content[int_index + 2:int_index + 2 + int_len].hex(), 16)
            print_snmp_trap(i,key,int_num)
            #print('INTEGER ' + str(int_num))
            i = i + 2 + int_len
            break

        if hit == 0:
            i += 1
        # print('index '+str(i))
        if i >= snmp_trap_content_len:
            break

    return snmp_ver,positon_bias

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48



sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 2162))

while True:

    positon_bias = 0
    snmp_ver = ''

    buf, addr = sock.recvfrom(10000)
    #print(buf)
    len_buf = (len(buf))
    #print("{0:x}".format(len_buf))
    hex_buf = (buf.hex())
    #print(hex_buf)
    #print(type(hex_buf)) #str
    #print(type(buf))
    #print(type(str(addr)))   #str
    print("Snmp Trap message from {0:s}".format(str(addr)))

    
    '''
       print(bytes.fromhex('7075626c6963'))
       >b'public'
       
       
       hex_str='0x73'
       int_dec = int(hex_str,16)
       print(int_dec)
       >115

       
    '''
    parse_snmp_trap(buf)

    print('-'*100)