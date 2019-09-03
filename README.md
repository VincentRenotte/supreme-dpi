# supreme-dpi
ébauche de dissecteur protocolaire S7
## How to run it
Clone this repository in your go folder
run the following command :

`go install github.com/VincentRenotte/supreme-dpi`

It will create a binary file in the bin of your go environment. Go there and just do :

`supreme-dpi`

## A few words
I use github.com/google/gopacket to extract the packets from the pcap files. Once done, the function handlePacket will process it and read the payload of applicatio layer.

I had to use one global variable in order to give an ID to each S7 operations while discarding other layers (TCP, IP, MAC...) from the final output

## FAQ
When trying to run this, I get 

`fatal error: pcap.h: No such file or directory compilation terminated.`

Install the following :

`sudo apt-get install libpcap-dev`