#CTF-write-up

How to test exploit locally:
----------------------------

1. `git clone https://github.com/Naetw/CTF-write-up.git`
2. `cd ${The directory you want to play}`
3. `ncat -vc ./${binary file} -kl 127.0.0.1 4000` # This will run the binary locally for test 
4. Then open another terminal (use [tmux](https://tmux.github.io)! or just open another terminal tab)
5. `cd` to the same directory
6. `./ex.py` # execute the exploit
7. Then... GET THE SHELL!!!!

Bug report:
-----------

If there is any bug, please tell me!
