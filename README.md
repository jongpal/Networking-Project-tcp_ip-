# TCP/IP Networking-Project

- [x] Create Network topologies, you can include both routers & switches in same topology
- [x] Automatic Arp resolution, Mac Learning
- [x] could implement spf(shortest path first) algorithm to prevent loop problem
- [x] VLAN(virtual lan), Inter-vlan routing supported
- [x] Ping
- [ ] checksum implementation
- [ ] Logging mechanism
- [ ] fragmentation
- [ ] timer

* ### How to make topology you want
  #### you can view some example topologies in **src/topology.c** file
  1. _make topology files_
    ```
    vim topology_example.c
    ```
  2. _make your own topology configuration_
  3. _include that topology function to **test/testapp.c** file_ 


* ### How to test this project

  1. Download this repo
  2. Makefile
    ```Makefile
    make
    ```
  3. run **.exe** file
    ```
    ./test.exe
    ```
  4. view some **commands** you can make
    ```
    .
    ```
    this will show you commands list like this\
    <img width="448" alt="Screen Shot 2021-06-25 at 2 42 45 PM" src="https://user-images.githubusercontent.com/70065848/123375416-b495fe80-d5c3-11eb-8759-4b2ce1af93a4.png">
* ### to remove *.o files or *.exe files
```Makefile
make clean
```
