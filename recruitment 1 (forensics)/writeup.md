Pretty basic pcap file with a bunch of tcp and http requests and responses.<br /> 
<br />
The first thing we do is to filter the pcap file for HTTP requests and responses, which is done by using the filter `http` in Wireshark.<br />
After that, we look through each HTTP login attempt and find the packet which seems to have the accurate login credentials.<br />
Well there's a clear hint in the question about the usage of ROT-13, so we can use that to decode the password from the packet which can seemingly looks like a ROT13 string of the flag.<br />
<br />
In packet 20, we can see the HTTP request with the username and password where the pass has the value `UGO{q0_L0h_xa0J_qN_jNl}`<br />
Upon decoding with ROT13, we get the flag as `HTB{d0_Y0u_kn0W_dA_wAy}`.<br />