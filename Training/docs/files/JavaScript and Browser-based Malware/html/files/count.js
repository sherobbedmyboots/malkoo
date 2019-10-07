var i=1;

//Double a number every 0.3 seconds

function timedCount() {
    i=i*2;
    postMessage(i);
    setTimeout("timedCount()", 300);
}
timedCount();