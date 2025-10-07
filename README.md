# GenshinCb2PacketSniffer-Rewrite
Rewritten in C++

# Usage
- Update the ec2b key in `src\ec2b_data.cpp`
- Place your built `MinHook.x64.lib` in `third_party\minhook\lib\x64`
- Run `mkdir build && cd build && cmake ..`
- Compile the solution
- Inject on startup

Should work on cbt1, but is untested (will also require you to update cmdids)

Copyright© Hiro420, ec2b code copyright goes to **Mero** and **Hotaru**
ec2b code's license is in `credit_license` folder