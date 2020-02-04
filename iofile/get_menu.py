pattern = re.compile(b'\d\..+')
mainmenu = pattern.findall(r())
ask="Command:"
response='20'
pattern_fun=re.compile(b'\w+')
if mainmenu:
    for item in mainmenu[:-1]:
        function="def {0}(a):\n\tru('{1}')\n\tsl('{2}')\n".format(bytes.decode(pattern_fun.findall(item[2:])[0]),ask,bytes.decode(item[0:1]))
        sl(item[0:1])
        while(True):
            receive = r()
            if(pattern.findall(receive)!=mainmenu):
            #submenu = pattern.findall(receive)
            #if submenu:
            #    print(submenu)
                sl(response)
                function+="\tru('{0}')\n".format(bytes.decode(receive))
                function+="\tsl(str(a))"
            else:
                break
        print(function)    
else:
    print("error")