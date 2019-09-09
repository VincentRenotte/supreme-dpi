# supreme-dpi
Rough sketch of protocolar dissector for Siemens communication protocol S7 
## How to run it
Clone this repository in your go folder :

`go get github.com/VincentRenotte/supreme-dpi`

Create the executable :

`go install github.com/VincentRenotte/supreme-dpi`

It will create a binary file in the bin of your go environment. Go there and just do :

`supreme-dpi`

One can change the used pcap files at line 15 :
```golang
var (
	//pcapFile string = os.Getenv("GOPATH") + "/src/github.com/VincentRenotte/supreme-dpi/files/s7comm_varservice_libnodavedemo_bench.pcap"
	pcapFile string = os.Getenv("GOPATH") + "/src/github.com/VincentRenotte/supreme-dpi/files/s7comm_varservice_libnodavedemo.pcap"
)
```

## A few words
I use github.com/google/gopacket to extract the packets from the pcap files. Once done, the function handlePacket will process it and read the payload of application layer.

The program is able to extract any of the fields among the followings :
1. ROSCTR    
2. PDU Referencer
3. Para length
4. Data length  
5. Function 
6. Variable Type 
7. DB Number 
8. Area      
9. Address   
10. Returned Code 
11. Data  
12. error Class
13. error Code  
14. variable Specification
15. address Specification Length
16. syntaxId
17. PDU Length
18. Item length

Only the 11 first element are displayed in final output in order to increase readibility. However, it would take very little effort to add any of the following fields. It is also fairly easy to extract information about any other layer (MAC, IP or TCP for instance).

An important note is that I chosed a 2-dimensionnal slice to store the list of payloads and their attributes. On one hand, this allows a more natural way to read and display the output. On the other hand, adding more fields to handle different type of messages might be tricky because of the Non-Applicable (N/A) fields. To make it more flexible, one option would be to **create a struct "S7payload"** with field initiated to "N/A" in order to avoid the need of paddling the slice. 

Currently, only BYTE will be displayed for variable TYPE (line 100). One may add the necessary cases if other types are to be expected :
```golang
transportSize := payload[22+offset]
variableType := ""
if transportSize == 2 {
    variableType = "BYTE"
}
```

The "offset" variable is here because according to the type of message some fields are present or not. Thus it is necessary to "paddle" when reading the payload slice.

## Troubleshooting
When trying to run this, I get 

`fatal error: pcap.h: No such file or directory compilation terminated.`

Install the following :

`sudo apt-get install libpcap-dev`
