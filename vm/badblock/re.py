def getop(i):
  opc = ''
  opc += op[str(opcodes[i])]
  oprand1=opcodes[i+2]+opcodes[i+3]*0x100
  if(oprand1&0x8000):
    opc += str(oprand1-0x10000)
  else:
    opc += str(oprand1)
  opc += ' '
  opc += str(opcodes[i+4]+opcodes[i+5]*0x100)
  return opc

opcodes_translate=map(getop,range(0,len(opcodes),6))
for i in  range(0,len(opcodes_translate)):
  print(i,opcodes_translate[i])
cc=[]
for i in range(20):
  c=data1[i*2]^((i+36)*2)
  cc.append(c)

#xor
for i in range(19,3,-1):
  cc[i]=cc[i-4]^cc[i]

print(''.join([chr(item) for item in cc]))
#flag{Y0u_ar3_S0co0L}   