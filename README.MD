Every single game on Steam is cracked by just having a steam_api emulator that takes all the calls and gives the application the illusion they're connected and own the product. This launcher verifies the validity of signature on the steam_api DLL to ensure it's the official Valve one.

This is simple to bypass and should be obfuscated but the interesting part is this all runs as a replacement launcher for Unity so you can do your own cool looking thing referencing this code. Maybe just take the interop method for launching the unity game. 

You should reference the Program.cs as it also performs a validation of the game assembly for mods and if so, disables achievements. Essentially, you want to clone this and take what you need. 


           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
                   Version 2, December 2004
 
Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>

Everyone is permitted to copy and distribute verbatim or modified
copies of this license document, and changing it is allowed as long
as the name is changed.
 
           DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
  TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION

 0. You just DO WHAT THE FUCK YOU WANT TO.
 
 
 (if you use it give me a holler, i've got plenty of small things sitting here to mess with steam piracy)
