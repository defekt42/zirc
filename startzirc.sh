#!/bin/sh

tmux split-window -t zirc -v -l 1 ~/.suckless/irc/zirc-sec/./zircin.sh #changed 2 to 1
# added stty -echo; to kill double post
stty -echo; ~/.suckless/irc/zirc-sec/./zirc-sec-stable-v1.7 irc.libera.chat 6697 defekt prompt

#~/.suckless/irc/./circ zirc-posix zirc-posix 127.0.0.1 6697 "##" "dh00l422" #

# Start with tmux new -s zirc -n Double-Octothorpe ~/.suckless/irc/zirc-sec/./startzirc.sh

