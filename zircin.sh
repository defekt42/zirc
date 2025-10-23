#!/bin/sh

prompt="zirc> "
pane="zirc.0"

while read -r -u input?"${prompt}" ; do
    tmux send -t ${pane} "${input}" Enter
    [[ "${input}" == ":quit" ]] && exit 0
done

# Create an input pane for zirc in tmux. Avoid problems when you receive new messages while you type one yourself. 