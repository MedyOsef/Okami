import PySimpleGUI as sg # for the GUI part
import scapy.all as scp # for packet capturing
import scapy.arch.windows as scpwinarch # for windows interfaces
from scapy.arch  import get_if_list# for linux interfaces
import threading # for threading the sniffing function of scapy
import platform
import matplotlib.pyplot as plt


sg.theme("DarkGrey15")
# Ok so first lets define the structure of a rule
# her what
pktsummarylist = [] # this will hold the packet summaries for the captured packets
updatepklist = False # Initially false since we haven't yet started capturing packets
menu_def = [['&File', ['!&Open', '&Save::savekey', '---', '&Properties', 'E&xit']], ['&Help', ['&About...']]]

layout = [[sg.Menu(menu_def)],
    [sg.Button("Start Capture", key="-startcap-"),
     sg.Button("Stop Capture", key="-stopcap-"),
     sg.Button("Save Capture", key="-savepcap-")],
    [sg.Text("ALL PACKETS", font=('Helvetica Bold', 20))],
    [sg.Listbox(key="-pktsall-",
                size=(100, 20),
                enable_events=True,
                values=pktsummarylist)]
]

window = sg.Window("Ōkami",
                   layout,
                   size=(1600, 800))

pkt_list = [] # Will hold the actual packet objects

# let's get the interfaces names
ifaces = [str(x["name"]) for x in scpwinarch.get_windows_if_list()]
capiface = ifaces[0] #We just need the first interface for now


# now let's write the pkt process function
# this function defines what to do with each captured packet
def pkt_process(pkt):
    global pktsummarylist
    global pkt_list
    # Just getting access to the list from within the function
    pkt_summary = pkt.summary() # Get packet summary
    pktsummarylist.append(pkt_summary) # add to packet summary list
    return

sniffthread = threading.Thread(target=scp.sniff,
                               kwargs={'prn': pkt_process,
                                       "filter": ""},
                               daemon = True)
#Now we have our thread set up, lets call the thread.start() method
sniffthread.start()

# packet capture stopped by user
# now with our pkt process function done, let's first write our
# windows event, value loop first

while True:
    event, values = window.read() # Read buttonclicks, values etc. from our window event,value loop first

    if event == "-startcap-":
        # start capturing packets
        updatepklist = True
        # We have to empty pkt list every time we start new capture
        pktsummarylist = []
        pkt_list = []
        #pkt_list = scp.sniff(iface=capiface, prn=pkt_process)

        while True:
            event, values = window.read(timeout=10) # Read buttonclicks, values etc. from
            if event == "-stopcap-":
                updatepklist = False # packet capture stopped by user
                break


            # Now we have to update our listbox while capturing packets
            #for that, we first have to capture our packets
            # we need to thread that since it has to run simultaneously with our window.read() function
            #now lets update our listbox with packets captured
            if event == sg.TIMEOUT_EVENT:
                window["-pktsall-"].update(values=pktsummarylist, scroll_to_index=len(pktsummarylist))

# This should give us a continous packet capture stream
# let's see if this works
# As you can see, we are actually capturing live packets
# in our next part of this series, we will be introducing rules
# we will write that will filter packets out for <us.