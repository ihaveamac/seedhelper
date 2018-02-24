[![JavaScript Style Guide](https://cdn.rawgit.com/standard/standard/master/badge.svg)](https://github.com/standard/standard)

# seedhelper
A tool to assist users of the seedminer method to communicate.

# How to run
```
sudo apt install redis # or equivalent
npm i
# optional: copy seedminer saves to /static/ugc/data as a basis for automatic msed db
NODE_ENV=production SESSION_SECRET=dontsharethis node seedhelper.js
```
Runs on port 3000 by default, use a proxy like nginx or caddy or change PORT environment variable to 80.

# How to use
Read the help page on website for more information.

# Credits
* [zoogie](https://github.com/zoogie) for creating the seedminer toolset and finding the movable.sed vulnerability.
* [saibotu](https://github.com/saibotu), [jason0597](https://github.com/jason0597), [Kartik](https://github.com/Pirater12), and [Chromaryu](https://github.com/knight-ryu12) for testing and help.
* Nintendo for designing horribly broken systems :D
* Everybody who helps this system stay alive by finding movable_part1 and bruteforcing movable for other users.
