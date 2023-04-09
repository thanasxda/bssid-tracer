############################
# b/ssid tracer wip
# github @ thanasxda
############################

# IMPORT LIBRARIES ##############
from tkinter import *
import requests
import json
import re
import os
import subprocess
import tkinter.filedialog
from PIL import Image, ImageTk
############################


# MAIN WINDOW ##############
root = Tk()
root['bg']='black'
root.title('B/SSID-TRACER')
############################


# LOGO ##############
path = "src/logo.png"
load = Image.open(path)
load.resize((119,114), Image.Resampling.LANCZOS)
render = ImageTk.PhotoImage(load)
root.iconphoto(False, render)
cv = Canvas(root, highlightthickness=0, height=115, width=300)
cv['bg']='black'
cv.grid(column=0, columnspan=5)
cv.create_image(150, 0, image=render, anchor='n')
############################


# ERROR MESSAGES ##############
# 0 ##############
def openWindow0():
	Window0 = Toplevel(root)
	Window0['bg']='black'
	Window0.title("B/SSID-TRACER")
	message="Input not found!"
	Label(Window0,bg='#000', fg='orange', borderwidth=4, relief="solid", text=message).grid(column=0, row=0)
	btnok = Button(Window0, text="OK", borderwidth=4, relief="solid", bg='#000', fg='orange', command=Window0.destroy)
	btnok.grid(column=0, row=2)
	
# 1 ##############
def openWindow1():
	Window1 = Toplevel(root)
	Window1['bg']='black'
	Window1.title("B/SSID-TRACER")
	message="Incorrect input!"
	Label(Window1,bg='#000', fg='orange', borderwidth=4, relief="solid", text=message).grid(column=0, row=0)
	btnok = Button(Window1, text="OK", borderwidth=4, relief="solid", bg='#000', fg='orange', command=Window1.destroy)
	btnok.grid(column=0, row=2)
	
# 2 ##############
def openWindow2():
	Window2 = Toplevel(root)
	Window2['bg']='black'
	Window2.title("B/SSID-TRACER")
	message="Check your internet connection!"
	Label(Window2,bg='#000', fg='orange', borderwidth=4, relief="solid", text=message).grid(column=0, row=0)
	btnok = Button(Window2, text="OK", borderwidth=4, relief="solid", bg='#000', fg='orange', command=Window2.destroy)
	btnok.grid(column=0, row=2)
	
# 3 ##############
def openWindow3():
	Window3 = Toplevel(root)
	Window3['bg']='black'
	Window3.title("B/SSID-TRACER")
	message="Your API key failed to authenticate!"
	Label(Window3,bg='#000', fg='orange', borderwidth=4, relief="solid", text=message).grid(column=0, row=0)
	btnok = Button(Window3, text="OK", borderwidth=4, relief="solid", bg='#000', fg='orange', command=Window3.destroy)
	btnok.grid(column=0, row=2)
############################

# API CONFIG ##############
def openWindowAPI():
	WindowAPI = Toplevel(root)
	WindowAPI['bg']='black'
	WindowAPI.title("B/SSID-TRACER")
	message="Enter Wigle API key:"
	Label(WindowAPI,bg='#000', fg='orange', borderwidth=4, relief="solid", text=message).grid(column=0, row=0)
	#cat="echo $(awk -F 'wigle = ' '{print $2}' $PWD/src/api.env)"
	#output = subprocess.check_output(cat, shell=True)
	#cat=open("src/api.env", "r")
	#cleanoutput=cat.read().rstrip('\n')
	#cleanoutput = output.decode(encoding='UTF-8')
	wigleapi = StringVar(WindowAPI, value="")
	wigleapiTf = Entry(WindowAPI, textvariable=wigleapi).grid(column=0, row=1)
	#cat.close()
	#cat=open("src/api.env", "a")
	#btn_wigleapi = Button(WindowAPI, text="Save API Keys", borderwidth=4, relief="solid", bg='#000', fg='orange', command=os.system("echo 'wigle = "+wigleapi.get()+"' > src/api.txt"))
	def write():
		f = open("src/api.env", "w")
		f.write(wigleapi.get())
		f.close()
	btn_wigleapi = Button(WindowAPI, text="Save API Keys", borderwidth=4, relief="solid", bg='#000', fg='orange', command=write)
	btn_wigleapi.grid(column=0, row=2)
############################


# B/SSID ENTRY OPTIONS ##############
# b/ssid input fields ##############
#cat="ip -o link | awk -F link/ether '{print $2}' | awk '{print $1}' | tail -n1"
#output = subprocess.check_output(cat, shell=True)
Label(root,bg='#000', fg='orange', text='Enter BSSID mac address: ').grid(column=0, row=1)
mac = StringVar(root, value="")
macTf = Entry(root, textvariable=mac).grid(column=0, row=2)
#regexp = "(([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})|(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})"
#Label(root, text="\nYour ethernet's mac address is  "+str(mac.get()[2:19] +"\n")).grid(column=0, row=0)

Label(root,bg='#000', fg='orange', text='Enter SSID (Wifidb only): ').grid(column=0, row=3)
ssid = StringVar(root, value="")
ssidTf = Entry(root, textvariable=ssid).grid(column=0, row=4)
############################

# requests for mylnikov json ##############
def searchDb():
		requ = requests.get("https://api.mylnikov.org/geolocation/wifi?v=1.2&bssid="+mac.get())
		resp = requ.content
		json_pars = json.loads(resp)
		array_request=json_pars["result"]
		request_data = json.dumps(array_request)
		if (request_data == "200"): # found
			array_latitude = json_pars["data"]["lat"]
			array_longitude = json_pars["data"]["lon"]
			latitude_data = json.dumps(array_latitude)
			longitude_data = json.dumps(array_longitude)
			os.system("xdg-open 'https://earth.google.com/web/@"+latitude_data+","+longitude_data+"'")
		elif (request_data == "404"):
			openWindow0() # entry not found
		elif (request_data == "400"):
			openWindow1() # incorrect entry
		else:
			openWindow2() # connection issue
btn_mlnkv = Button(root,bg='#000', fg='orange', text='Search Mylnikov w/ Google (BSSID)', borderwidth=4, relief="solid", command=searchDb)
btn_mlnkv.grid(column=0, row=5)

# requests for wifidb json ##############
def searchWifiDb():
		requ = requests.get("https://wifidb.net/wifidb/api/geojson.php?func=exp_search&ssid="+ssid.get()+"&mac="+mac.get()+"&radio=&chan=&auth=&encry=&sectype=&json=0&labeled=0")
		resp = requ.content
		json_pars = json.loads(resp)
		array_request=json_pars["features"][0]["properties"]["mac"]
		request_data = json.dumps(array_request)
		if request_data: # found
			array_latitude = json_pars["features"][0]["properties"]["lat"]
			array_longitude = json_pars["features"][0]["properties"]["lon"]
			latitude_data = json.dumps(array_latitude)
			longitude_data = json.dumps(array_longitude)
			os.system("xdg-open 'https://earth.google.com/web/@"+latitude_data+","+longitude_data+"'")
		elif not request_data:
			openWindow0() # entry not found
btn_wdb = Button(root,bg='#000', fg='orange', text='Search Wifidb w/ Google (B/SSID)', borderwidth=4, relief="solid", command=searchWifiDb)
btn_wdb.grid(column=0, row=6)

# requests for wigle json ##############
def wigle():
	cat=open("src/api.env", "r")
	cleanoutput=cat.read().rstrip('\n')
	headers = {'Accept': 'application/json', 'Authorization': f'Basic {cleanoutput}'}
	url = 'https://api.wigle.net/api/v2/network/search'
	if ssid != "":
		wigpar = {'ssid': ssid.get(), 'resultsPerPage': 1}
	if mac != "":
		wigpar = {'netid': mac.get(), 'resultsPerPage': 1}
	if ssid != "" and mac != "":
		wigpar = {'ssid': ssid.get(), 'netid': mac.get(), 'resultsPerPage': 1}
	requ = requests.get(url, headers=headers, params=wigpar)
	resp = requ.content
	json_pars = json.loads(resp)
	array_request = json_pars["results"]
	request_data = json.dumps(array_request)
	cat.close()
	if (array_request != 0): # found
		array_latitude = json_pars["trilat"]
		array_longitude = json_pars["trilong"]
		latitude_data = json.dumps(array_latitude)
		longitude_data = json.dumps(array_longitude)
		os.system("xdg-open 'https://earth.google.com/web/@"+latitude_data+","+longitude_data+"'")
	elif (request_data == "404"):
		openWindow0() # entry not found
	elif (request_data == "400"):
		openWindow1() # incorrect entry
	elif (request_data == "401"):
		openWindow3() # incorrect api
	else:
		openWindow2() # connection issue
btn_wigle = Button(root,bg='#000', fg='orange', text='Search Wigle /w Google (B/SSID)', borderwidth=4, relief="solid", command=wigle)
btn_wigle.grid(column=0, row=7)

# search wifidb browser ##############
def searchBrowser():
	os.system("xdg-open 'https://wifidb.net/wifidb/opt/results.php?&ssid="+ssid.get()+"&mac="+mac.get()+"&radio=&chan=&auth=&encry=&sectype='")
btn_wdbon = Button(root,bg='#000', fg='orange', text='Search Wifidb online (B/SSID)', borderwidth=4, relief="solid", command=searchBrowser)
btn_wdbon.grid(column=0, row=8)

# search wigle browser ##############
def searchBrowser():
	os.system("xdg-open 'https://wigle.net/mapsearch?'")
btn_wigleon = Button(root,bg='#000', fg='orange', text='Search Wigle online (B/SSID)', borderwidth=4, relief="solid", command=searchBrowser)
btn_wigleon.grid(column=0, row=9)
############################


# COORDINATE OPTIONS ##############
# coordinate input fields ##############
Label(root,bg='#000', fg='orange', text='Longitude: ').grid(column=0, row=10)
llong = StringVar(root, value="")
llongTf = Entry(root, textvariable=llong).grid(column=0, row=11)

Label(root,bg='#000', fg='orange', text='Latitude: ').grid(column=0, row=12)
llat = StringVar(root, value="")
llatTf = Entry(root, textvariable=llat).grid(column=0, row=13)
############################

# search coordinates ##############
def manualS():
	os.system("xdg-open 'https://earth.google.com/web/@"+llat.get()+","+llong.get()+"'")
btn_crdnts = Button(root,bg='#000', fg='orange', text='Search coordinates', borderwidth=4, relief="solid", command=manualS)
btn_crdnts.grid(column=0, row=14)
############################


# IP OPTIONS ##############
# ip input field ##############
Label(root,bg='#000', fg='orange', text='Enter ip: ').grid(column=1, row=1)
ipc = StringVar(root, value="")
ipcTf = Entry(root, textvariable=ipc).grid(column=1, row=2)
############################

# ip search ripestat ##############
def ipL():
	os.system("xdg-open 'https://stat.ripe.net/app/launchpad/S1_"+ipc.get()+"_C13eC31eC6eC14eC27eC10e'")
btn_rpst = Button(root,bg='#000', fg='orange', text='Search Ripestat', borderwidth=4, relief="solid", command=ipL)
btn_rpst.grid(column=1, row=3)

# ip search shodan ##############
def Sho():
		os.system("xdg-open 'https://www.shodan.io/search?query="+ipc.get()+"'")
btn_sho = Button(root,bg='#000', fg='orange', text='Search Shodan', borderwidth=4, relief="solid", command=Sho)
btn_sho.grid(column=1, row=4)

# ip search abuse ipdb ##############
def abIPDB():
		os.system("xdg-open 'https://www.abuseipdb.com/check/"+ipc.get()+"'")
btn_sho = Button(root,bg='#000', fg='orange', text='Search AbuseIPDB', borderwidth=4, relief="solid", command=abIPDB)
btn_sho.grid(column=1, row=5)

# ip nmap scan ##############
def ipS():
	os.system("nmap -v -p \"*\" "+ipc.get())
btn_prts = Button(root,bg='#000', fg='orange', text='Scan ports', borderwidth=4, relief="solid", command=ipS)
btn_prts.grid(column=1, row=6)

# ip traceroute ##############
def trC():
	os.system("traceroute "+ipc.get())
btn_trc = Button(root,bg='#000', fg='orange', text='Traceroute', borderwidth=4, relief="solid", command=trC)
btn_trc.grid(column=1, row=7)

# ip ping ##############
def pnG():
	os.system("ping -c4 "+ipc.get())
btn_png = Button(root,bg='#000', fg='orange', text='Ping', borderwidth=4, relief="solid", command=pnG)
btn_png.grid(column=1, row=8)

# aircrack-ng/aireplay-ng deauth ##############
Label(root,bg='#000', fg='orange', text='Target mac address: ').grid(column=1, row=9)
client = StringVar(root, value="")
clientTf = Entry(root, textvariable=llat).grid(column=1, row=10)
def dAuth():
	os.system("aireplay-ng -0 1 -a "+mac.get()+" -c "+client.get()+" $(ip -o link | grep -i wlan | awk -F ':' '{print $2}' | head -n1)mon")
btn_client = Button(root,bg='#000', fg='orange', text='Deauthenticate target', borderwidth=4, relief="solid", command=dAuth)
btn_client.grid(column=1, row=11)
############################

# intelx ##############
Label(root,bg='#000', fg='orange', text='_IntelligenceX').grid(column=1, row=12)
ix = StringVar(root, value="")
ixTf = Entry(root, textvariable=ix).grid(column=1, row=13)
def siX():
		os.system("xdg-open 'https://intelx.io/?s="+ix.get()+"'")
btn_ix = Button(root,bg='#000', fg='orange', text='Search Intelx', borderwidth=4, relief="solid", command=siX)
btn_ix.grid(column=1, row=14)
############################


# EXTRA OPTIONS ##############
Label(root,bg='#000', fg='orange', text='Extras: ').grid(column=2, row=1)
############################

# e-mail headers ##############
def anEm():
	os.system("xdg-open 'https://mha.azurewebsites.net/'")
btn_eml = Button(root,bg='#000', fg='orange', text='Analyze e-mail headers', borderwidth=4, relief="solid", command=anEm)
btn_eml.grid(column=2, row=2)

# netstat ##############
def netSt():
	os.system('echo "\033[1;93m" ; netstat | grep -i "tcp\|udp" ; echo "\n" ; netstat -n | grep -i "tcp\|udp" ; sudo netstat -tulpn ; echo "\033[0m"')
btn_ntst = Button(root,bg='#000', fg='orange', text='Check Netstat', borderwidth=4, relief="solid", command=netSt)
btn_ntst.grid(column=2, row=3)

# wireshark ##############
def Wshark():
	os.system("xdg-open wireshark")
btn_wrshrk = Button(root,bg='#000', fg='orange', text='Start Wireshark', borderwidth=4, relief="solid", command=Wshark)
btn_wrshrk.grid(column=2, row=4)

# ettercap ##############
def Ecap():
	os.system("xdg-open ettercap")
btn_etrcp = Button(root,bg='#000', fg='orange', text='Start Ettercap', borderwidth=4, relief="solid", command=Ecap)
btn_etrcp.grid(column=2, row=5)

# metasploit ##############
def Msploit():
	os.system("msfconsole")
btn_mtsplt = Button(root,bg='#000', fg='orange', text='Start Metasploit', borderwidth=4, relief="solid", command=Msploit)
btn_mtsplt.grid(column=2, row=6)

# routersploit ##############
def Rsploit():
	os.system("routersploit")
btn_rtrsplt = Button(root,bg='#000', fg='orange', text='Start Routersploit', borderwidth=4, relief="solid", command=Rsploit)
btn_rtrsplt.grid(column=2, row=7)

# maltego ##############
def Mgo():
	os.system("xdg-open maltego")
btn_mltg = Button(root,bg='#000', fg='orange', text='Start Maltego', borderwidth=4, relief="solid", command=Mgo)
btn_mltg.grid(column=2, row=8)

# grabify ##############
def gbfy():
	os.system("xdg-open 'https://grabify.link/'")
btn_grbfy = Button(root,bg='#000', fg='orange', text='Grabify url shortener', borderwidth=4, relief="solid", command=gbfy)
btn_grbfy.grid(column=2, row=9)

# dictionary ##############
def selDict():
	dictFile = tkinter.filedialog.askopenfilename(initialdir='~/Downloads', title='', filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
	if mac.get() != "":
		os.system("'grep -i "+mac.get()+" "+dictFile.get()+"'")
	if ssid.get() != "":
		os.system("'grep -i "+ssid.get()+" "+dictFile.get()+"'")
btn_dict = Button(root,bg='#000', fg='orange', text='Search dictionary for B/SSID', borderwidth=4, relief="solid", command=selDict)
btn_dict.grid(column=2, row=10)
############################


# ATTACK OPTIONS ##############
# aircrack-ng ##############
# airmon #############
def airMon():
	os.seteuid(1000)
	os.system("if airmon-ng | grep -qi wlan ; then airmon-ng stop $(ip -o link | grep -i wlan | awk -F ':' '{print $2}' | head -n1)mon ; else sudo airmon-ng start $(ip -o link | grep -i wlan | awk -F ':' '{print $2}' | head -n1)mon ; fi")
btn_airmn = Button(root,bg='#000', fg='orange', text='Start/stop monitor mode', borderwidth=4, relief="solid", command=airMon)
btn_airmn.grid(column=2, row=11)

# airodump #############
def airoD():
	os.seteuid(1000)
	os.system("airodump-ng $(ip -o link | grep -i wlan | awk -F ':' '{print $2}' | head -n1)mon --bssid "+mac.get())
btn_airmn = Button(root,bg='#000', fg='orange', text='Airodump BSSID', borderwidth=4, relief="solid", command=airoD)
btn_airmn.grid(column=2, row=12)

# reaver ##############
def wps():
		os.system("reaver -i $(ip -o link | grep -i wlan | awk -F ':' '{print $2}' | head -n1)mon -b "+mac.get())
btn_rvr = Button(root,bg='#000', fg='orange', text='Reaver BSSID attack', borderwidth=4, relief="solid", command=root.destroy)
btn_rvr.grid(column=2, row=13)
############################


# EXTERNAL VISIT OPTIONS ##############
Label(root,bg='#000', fg='orange', text='For more: ').grid(column=3, row=1)
############################

# osint ##############
def visitOsint():
	os.system("xdg-open 'https://osintframework.com/'")
btn_osint = Button(root,bg='#000', fg='orange', text='Visit OSINT framework', borderwidth=4, relief="solid", command=visitOsint)
btn_osint.grid(column=3, row=2)

# exploit-db ##############
def eDB():
		os.system("xdg-open 'https://www.exploit-db.com/'")
btn_edb = Button(root,bg='#000', fg='orange', text='Visit Exploit-db', borderwidth=4, relief="solid", command=eDB)
btn_edb.grid(column=3, row=3)

# pwnd ##############
def pwnd():
		os.system("xdg-open 'https://haveibeenpwned.com/'")
btn_pwnd = Button(root,bg='#000', fg='orange', text='Visit HaveIBeenPwned', borderwidth=4, relief="solid", command=pwnd)
btn_pwnd.grid(column=3, row=4)

# dehashed ##############
def dhs():
		os.system("xdg-open 'https://dehashed.com/'")
btn_dhs = Button(root,bg='#000', fg='orange', text='Visit Dehashed', borderwidth=4, relief="solid", command=dhs)
btn_dhs.grid(column=3, row=5)

# breachdirectory ##############
def bdir():
		os.system("xdg-open 'https://breachdirectory.com/search'")
btn_ddir = Button(root,bg='#000', fg='orange', text='Visit Breachdirectory', borderwidth=4, relief="solid", command=bdir)
btn_ddir.grid(column=3, row=6)

# crackstation ##############
def crst():
		os.system("xdg-open 'https://crackstation.net/'")
btn_crst = Button(root,bg='#000', fg='orange', text='Visit Crackstation', borderwidth=4, relief="solid", command=crst)
btn_crst.grid(column=3, row=7)

# epieos ##############
def epieos():
		os.system("xdg-open 'https://epieos.com/'")
btn_epieos = Button(root,bg='#000', fg='orange', text='Visit Epieos', borderwidth=4, relief="solid", command=epieos)
btn_epieos.grid(column=3, row=8)
############################


# API KEYS ##############
Label(root,bg='#000', fg='orange', text='API Keys: ').grid(column=3, row=9)
btn_apk = Button(root,bg='#000', fg='orange', text='Configure API Keys', borderwidth=4, relief="solid", command=openWindowAPI)
btn_apk.grid(column=3, row=10)
############################


# DISCLAIMER & EXIT ##############
Label(root,bg='#000', fg='#f00', font=('Helvetica',6), text='DISCLAIMER: DOES NOT PROMOTE ILLEGAL ACTIVITIES\nUSE FOR ETHICAL/EDUCATIONAL PURPOSE ONLY\nRESPECT THE PRIVACY OF OTHERS!!!').grid(column=3, row=12)
Label(root,bg='#000', fg='orange', font=('Helvetica',8), text='by thanasxda').grid(column=3, row=13)
btn_exit = Button(root,bg='#000', fg='orange', text='Exit', borderwidth=4, relief="solid", command=root.destroy)
btn_exit.grid(column=3, row=14)
############################


# END ##############
root.mainloop()
############################
