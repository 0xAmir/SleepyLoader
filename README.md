# SleepyLoader
Incrementally developed loader for applying newely researched techniques for EDR bypasses

# Current Techniques
1. Stack spoofing via modified [advanced module stomping](https://dtsec.us/2023-11-04-ModuleStompin/)  
1.1 Sleep obfuscation via encryption + stomped module restoration during sleep cycles.
3. Advanced module stomping with Elastic bypass
4. Payload staging with OTA encryption while transferring and at rest in memory
5. API hashing for the HTTP payload staging module
6. 

# TODO
1. Implement stack size spoofing via recursion
2. Replace single byte XOR encryption with something better
3. Implement staging over HTTPS
