# supreme-dpi
ébauche de dissecteur protocolaire S7
## How to run
Clone this repository in your go folder
run the following command :
`go install github.com/VincentRenotte/supreme-dpi`
It will create a binary file in the bin of your go environment. Go there and just do :
`supreme-dpi`

## FAQ
When trying to run this, I get 
`fatal error: pcap.h: No such file or directory compilation terminated.`
Install the following :
`sudo apt-get install libpcap-dev`