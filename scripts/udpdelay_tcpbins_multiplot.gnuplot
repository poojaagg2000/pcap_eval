set term png
set output "printme.png"
set multiplot layout 2,1 title "Linear Mesh of Size 3" font ", 14" # multiplot mode (prompt changes to 'multiplot')
set tmargin 3

set key left box
#set size 1, 0.5

set lmargin at screen 0.20
set rmargin at screen 0.85
set bmargin at screen 0.6
set tmargin at screen 0.85


set title 'UDP packet delay'

set origin 0.0,0.5
#set xlabel 'Time (seconds)'
set xrange [0:60]
set ylabel 'Delay (ms)'
#set label 'file download start' at 20, 200
plot 'udpdelay_size3_seed4_data.csv' u 2:4 w l t 'Packet delay'


set lmargin at screen 0.20
set rmargin at screen 0.85
set bmargin at screen 0.10
set tmargin at screen 0.4

set title 'TCP data rate'
#set origin 0.0,0.0
set xlabel 'Time (seconds)'
set xrange [0:60]
set ylabel 'Data rate (kbps)'
plot 'tcpbins_size3_seed4_data.csv' u 2:4 w lines t 'Data rate'

unset multiplot   
replot
set term x11


