# b/ssid tracer wip
# github @ thanasxda

# import libs
from tkinter import *
import requests
import json
import re
import os
import subprocess
import tkinter.filedialog
from PIL import Image, ImageTk

# main window
root = Tk()
root['bg']='black'
root.title('B/SSID-TRACER')

# logo
path = "src/logo.png"
load = Image.open(path)
load.resize((119,114), Image.Resampling.LANCZOS)
render = ImageTk.PhotoImage(load)
root.iconphoto(False, render)
cv = Canvas(root, highlightthickness=0, height=115, width=300)
cv['bg']='black'
cv.grid(column=0, columnspan=3)
cv.create_image(150, 0, image=render, anchor='n')

# messages
def openWindow0():
	Window0 = Toplevel(root)
	Window0['bg']='black'
	Window0.title("B/SSID-TRACER")
	message="Input not found!"
	Label(Window0,bg='#000', fg='orange', borderwidth=4, relief="solid", text=message).grid(column=0, row=0)
	btnok = Button(Window0, text="OK", borderwidth=4, relief="solid", bg='#000', fg='orange', command=Window0.destroy)
	btnok.grid(column=0, row=2)

def openWindow1():
	Window1 = Toplevel(root)
	Window1['bg']='black'
	Window1.title("B/SSID-TRACER")
	message="Incorrect input!"
	Label(Window1,bg='#000', fg='orange', borderwidth=4, relief="solid", text=message).grid(column=0, row=0)
	btnok = Button(Window1, text="OK", borderwidth=4, relief="solid", bg='#000', fg='orange', command=Window1.destroy)
	btnok.grid(column=0, row=2)

def openWindow2():
	Window2 = Toplevel(root)
	Window2['bg']='black'
	Window2.title("B/SSID-TRACER")
	message="Check your internet connection!"
	Label(Window2,bg='#000', fg='orange', borderwidth=4, relief="solid", text=message).grid(column=0, row=0)
	btnok = Button(Window2, text="OK", borderwidth=4, relief="solid", bg='#000', fg='orange', command=Window2.destroy)
	btnok.grid(column=0, row=2)

# options
#cat="ip -o link | awk -F link/ether '{print $2}' | awk '{print $1}' | tail -n1"
#output = subprocess.check_output(cat, shell=True)
Label(root,bg='#000', fg='orange', text='Enter BSSID mac address: ').grid(column=0, row=1)
mac = StringVar(root, value="")
macTf = Entry(root, textvariable=mac).grid(column=0, row=2)
#regexp = "(([0-9A-Fa-f]{2}[-:]){5}[0-9A-Fa-f]{2})|(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})"

Label(root,bg='#000', fg='orange', text='Enter SSID (Wifidb only): ').grid(column=0, row=3)
ssid = StringVar(root, value="")
ssidTf = Entry(root, textvariable=ssid).grid(column=0, row=4)
#Label(root, text="\nYour ethernet's mac address is  "+str(mac.get()[2:19] +"\n")).grid(column=0, row=0)

def searchDb():
		requ = requests.get("https://api.mylnikov.org/geolocation/wifi?v=1.2&bssid="+mac.get())
		resp = requ.content
		json_pars = json.loads(resp)
		array_request=json_pars["result"]
		request_data = json.dumps(array_request)

		if (request_data == "200"):
			# found
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

btn_mlnkv = Button(root,bg='#000', fg='orange', text='Search Mylnikov database with Google maps (BSSID only)', borderwidth=4, relief="solid", command=searchDb)
btn_mlnkv.grid(column=0, row=5)

def searchWifiDb():
		requ = requests.get("https://wifidb.net/wifidb/api/geojson.php?func=exp_search&ssid="+ssid.get()+"&mac="+mac.get()+"&radio=&chan=&auth=&encry=&sectype=&json=0&labeled=0")
		resp = requ.content
		json_pars = json.loads(resp)
		array_request=json_pars["features"][0]["properties"]["mac"]
		request_data = json.dumps(array_request)
		if request_data:
			# found
			latitude_data = json_pars["features"][0]["properties"]["lat"]
			longitude_data = json_pars["features"][0]["properties"]["lon"]

			os.system("xdg-open 'https://earth.google.com/web/@"+latitude_data+","+longitude_data+"'")

		elif not request_data:
			openWindow0() # entry not found

btn_wdb = Button(root,bg='#000', fg='orange', text='Search Wifidb database with Google maps (both B/SSID)', borderwidth=4, relief="solid", command=searchWifiDb)
btn_wdb.grid(column=0, row=6)

def searchBrowser():
	os.system("xdg-open 'https://wifidb.net/wifidb/opt/results.php?&ssid="+ssid.get()+"&mac="+mac.get()+"&radio=&chan=&auth=&encry=&sectype='")

btn_wdbon = Button(root,bg='#000', fg='orange', text='Search Wifidb online (both B/SSID)', borderwidth=4, relief="solid", command=searchBrowser)
btn_wdbon.grid(column=0, row=7)

Label(root,bg='#000', fg='orange', text='Longitude: ').grid(column=0, row=8)
llong = StringVar(root, value="")
llongTf = Entry(root, textvariable=llong).grid(column=0, row=9)

Label(root,bg='#000', fg='orange', text='Latitude: ').grid(column=0, row=10)
llat = StringVar(root, value="")
llatTf = Entry(root, textvariable=llat).grid(column=0, row=11)

def manualS():
	os.system("xdg-open 'https://earth.google.com/web/@"+llat.get()+","+llong.get()+"'")

btn_crdnts = Button(root,bg='#000', fg='orange', text='Search coordinates', borderwidth=4, relief="solid", command=manualS)
btn_crdnts.grid(column=0, row=12)

Label(root,bg='#000', fg='orange', text='Enter ip: ').grid(column=0, row=13)
ipc = StringVar(root, value="")
ipcTf = Entry(root, textvariable=ipc).grid(column=0, row=14)

def ipL():
	os.system("xdg-open 'https://stat.ripe.net/app/launchpad/S1_"+ipc.get()+"'")

btn_rpst = Button(root,bg='#000', fg='orange', text='Search Ripestat', borderwidth=4, relief="solid", command=ipL)
btn_rpst.grid(column=0, row=15)

def ipS():
	os.system("nmap -v -p \"*\" "+ipc.get())

btn_prts = Button(root,bg='#000', fg='orange', text='Scan ports', borderwidth=4, relief="solid", command=ipS)
btn_prts.grid(column=0, row=16)

Label(root,bg='#000', fg='orange', text='Extras: ').grid(column=1, row=1)

def anEm():
	os.system("xdg-open 'https://mha.azurewebsites.net/'")

btn_eml = Button(root,bg='#000', fg='orange', text='Analyze e-mail headers', borderwidth=4, relief="solid", command=anEm)
btn_eml.grid(column=1, row=2)

def netSt():
	os.system('echo "\033[1;93m" ; netstat | grep -i "tcp\|udp" ; echo "\n" ; netstat -n | grep -i "tcp\|udp" ; echo "\033[0m"')
btn_ntst = Button(root,bg='#000', fg='orange', text='Check Netstat', borderwidth=4, relief="solid", command=netSt)
btn_ntst.grid(column=1, row=3)

def airMon():
	os.seteuid(1000)
	os.system("if airmon-ng | grep -qi wlan ; then airmon-ng stop $(ip -o link | grep -i wlan | awk -F ':' '{print $2}' | head -n1)mon ; else sudo airmon-ng start $(ip -o link | grep -i wlan | awk -F ':' '{print $2}' | head -n1)mon && sudo airodump-ng $(ip -o link | grep -i wlan | awk -F ':' '{print $2}' | head -n1)mon ; fi")

btn_airmn = Button(root,bg='#000', fg='orange', text='Start/stop Airmon', borderwidth=4, relief="solid", command=airMon)
btn_airmn.grid(column=1, row=4)

def Wshark():
	os.system("wireshark")

btn_wrshrk = Button(root,bg='#000', fg='orange', text='Start Wireshark', borderwidth=4, relief="solid", command=Wshark)
btn_wrshrk.grid(column=1, row=5)

def Ecap():
	os.system("ettercap-ng")

btn_etrcp = Button(root,bg='#000', fg='orange', text='Start Ettercap', borderwidth=4, relief="solid", command=Ecap)
btn_etrcp.grid(column=1, row=6)

def Msploit():
	os.system("msfconsole")

btn_mtsplt = Button(root,bg='#000', fg='orange', text='Start Metasploit', borderwidth=4, relief="solid", command=Msploit)
btn_mtsplt.grid(column=1, row=7)

def Rsploit():
	os.system("routersploit")

btn_rtrsplt = Button(root,bg='#000', fg='orange', text='Start Routersploit', borderwidth=4, relief="solid", command=Rsploit)
btn_rtrsplt.grid(column=1, row=8)

def Mgo():
	os.system("maltego")

btn_mltg = Button(root,bg='#000', fg='orange', text='Start Maltego', borderwidth=4, relief="solid", command=Mgo)
btn_mltg.grid(column=1, row=9)

def gbfy():
	os.system("xdg-open 'https://grabify.link/'")

btn_grbfy = Button(root,bg='#000', fg='orange', text='Grabify url shortener', borderwidth=4, relief="solid", command=gbfy)
btn_grbfy.grid(column=1, row=10)

def selDict():
	dictFile = tkinter.filedialog.askopenfilename(initialdir='~/Downloads', title='', filetypes=(("Text files", "*.txt"), ("All files", "*.*")))
	if mac.get() != 0:
		os.system("'grep -i "+mac.get()+" "+dictFile.get()+"'")
	if ssid.get() != 0:
		os.system("'grep -i "+ssid.get()+" "+dictFile.get()+"'")

btn_dict = Button(root,bg='#000', fg='orange', text='Select dictionary and find B/SSID from input', borderwidth=4, relief="solid", command=selDict)
btn_dict.grid(column=1, row=11)

Label(root,bg='#000', fg='orange', text='\nFor more: ').grid(column=1, row=12)

def visitOsint():
	os.system("xdg-open 'https://osintframework.com/'")

btn_osint = Button(root,bg='#000', fg='orange', text='Visit OSINT framework', borderwidth=4, relief="solid", command=visitOsint)
btn_osint.grid(column=1, row=13)

Label(root,bg='#000', fg='#f00', text='DISCLAIMER: Does NOT promote illegal activities\nUse for educational purpose and respect others privacy').grid(column=1, row=14)

Label(root,bg='#000', fg='orange', text='by thanasxda').grid(column=1, row=15)

btn_exit = Button(root,bg='#000', fg='orange', text='Exit', borderwidth=4, relief="solid", command=root.destroy, pady=2)
btn_exit.grid(column=1, row=16)



# end
root.mainloop()
