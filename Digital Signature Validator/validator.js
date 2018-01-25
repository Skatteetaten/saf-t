// Default bokmål tekster. Blir overskrevet i makeNewLables, så det er ingen vits i å endre de her!
// genererSignatur
var PRVKEYMISSING = "Privat nøkkel mangler!";
var SECKEYMISSING = "Hemmelig nøkkel mangler!";
// tekstTilSigneringOK
var TXTINPUT 		 = "Data til signering: ";
var ERRLENGTH 		 = "Feil format!";
var ERRSIGNATURE 	 = "Feil i <signature> fra forrige kvittering!";
var ERRTRANSDATEOK 	 = "Feil i transaksjonsdato <transDate>!";
var ERRTRANSTIMEOK 	 = "Feil i transaksjonsklokkeslett <transTime>!";
var ERRNROK 		 = "Feil i transaksjonsnummer <nr>!";
var ERRTRANSAMNTINOK = "Feil i beløp med mva <transAmntIn>!";
var ERRTRANSAMNTEXOK = "Feil i beløp uten mva <transAmntEx>!";
// RSA_SHA1
var RSAERRPRVKEY         = "Feil i privat nøkkel for RSA!";
var RSAPRVKEY            = "Nøkkel privat: ";
var RSAPUBKEYMISSING     = "Offentlig nøkkel mangler!";
var RSAERRPUBKEY         = "Feil i offentlig nøkkel!";
var RSAPUBKEY            = "Offentlig nøkkel: ";
var RSAPRVKEYNOT1024     = "RSA privat nøkkel er ikke 1024 bits!";
var RSAERRPRVKEYLENGTH   = "RSA privat nøkkel har feil lengde på noen elementer!";
var RSAPRVKEYEXPNOT65537 = "RSA privat nøkkel sin 'public exponent' er ikke 65537 som anbefalt.";
var RSAPRVKEYEXPBIG      = "RSA privat nøkkel sin 'private exponent' er for stor!";
var RSAPUBKEYNOT1024     = "RSA offentlig nøkkel er ikke 1024 bits!";
var RSAPUBKEYEXPNOT65537 = "RSA offentlig nøkkel sin 'public exponent' er ikke 65537 som anbefalt.";
var RSAPRVDIFFPUB        = "Privat og offentlig nøkkel passer ikke sammen!";
var RSAERRSIGNATURE      = "Feil i generering av signatur!";
// verifySignature
var NOSIGNATURE      = "Signatur ikke generert!";
var NOCASHSIGNATURE  = "Signaturen fra kassasystemet mangler!";
var ERRCASHSIGNATURE = "Feil i signatur fra kassasystemet: ";
var OKSIGNATURE      = "Signaturen er OK";
var ERRSIGNATURE     = "Signaturen er FEIL";
// HMAC_SHA1
var HMACKEYERR       = "HMAC feil i hemmelig nøkkel!";
var HMACKEYNOT128    = "HMAC hemmelig nøkkel er ikke 128 bits!";
var HMACERRSIGNATURE = "Feil i generering av signatur";
// flere steder
var INGENDATA = "Ingen data til signering!";
// help button
var SHOWUSERSGUIDE = "Vis bruksanvisning";
var HIDEUSERSGUIDE = "Gjem bruksanvisning";

var	helpVisibility = "none";

function genererSignatur() {
	var txt_string = document.getElementById('text').value;       // gets data from input text
	var privateKey = document.getElementById('privateKey').value; // gets data from input privateKey
	var publicKey = document.getElementById('publicKey').value;   // gets data from input publicKey
	var privateKeyLength = privateKey.length;
	var publicKeyLength = publicKey.length;
	
	if (txt_string.length == 0) {
		alert(INGENDATA);
		return false;
	}

	if (!tekstTilSigneringOK(txt_string)) {
		return;
	}
	
	if (privateKeyLength == 0) {
		if (document.getElementById('metode').value == 'SHA1withRSA')
			alert(PRVKEYMISSING);
		else
			alert(SECKEYMISSING);
		return;
	}
	
	if (document.getElementById('metode').value == 'SHA1withRSA') {
		RSA_SHA1(txt_string, privateKey, publicKey);
	} else {
		HMAC_SHA1(txt_string, privateKey);
	}
}

/***********************************************
* Format på tekst til signering: 
* 	signature;transDate;transTime;nr;transAmntIn;transAmntEx
* Eksempel:
* 	signature_from_previous_receipt;2014-01-24;23:59:59;123456789;1250.00;1000.00
************************************************/
function tekstTilSigneringOK(txt) {
	var txt_array = txt.split(";");
	if (txt_array.length < 6) {
		alert(TXTINPUT+ERRLENGTH);
		return false;
	}
	var signatureOK = isSignature(txt_array[0]);
	if (!signatureOK)
		alert(TXTINPUT+ERRSIGNATURE);
	var transDateOK = isDate(txt_array[1]);
	if (!transDateOK)
		alert(TXTINPUT+ERRTRANSDATEOK);
	var transTimeOK = isTime(txt_array[2]);
	if (!transTimeOK)
		alert(TXTINPUT+ERRTRANSTIMEOK);
	var nrOK = (txt_array[3].length <= 35);
	if (!nrOK)
		alert(TXTINPUT+ERRNROK);
	var transAmntInOK = isDecimal(txt_array[4]);
	if (!transAmntInOK)
		alert(TXTINPUT+ERRTRANSAMNTINOK);
	var transAmntExOK = isDecimal(txt_array[5]);
	if (!transAmntExOK)
		alert(TXTINPUT+ERRTRANSAMNTEXOK);
	return signatureOK && transDateOK && transTimeOK && nrOK && transAmntInOK && transAmntExOK;
}

function isLegalRSAPrivateKey(key) {
	var legal = true;
	var startString = "-----BEGIN RSA PRIVATE KEY-----";
	var endString = "-----END RSA PRIVATE KEY-----";

	if (key.substr(0,startString.length) != startString) {
		legal = false;
	}
	
	if (key.indexOf(endString) < 0) {
		legal = false;
	}

	return legal;
}

function isLegalRSAPublicKey(key) {
	var legal = true;
	var startString = "-----BEGIN PUBLIC KEY-----";
	var endString = "-----END PUBLIC KEY-----";

	if (key.substr(0,startString.length) != startString) {
		legal = false;
	}

	if (key.indexOf(endString) < 0) {
		legal = false;
	}

	return legal;
}

function isSignature(signatureString) {
	// Mangler test på gyldig signatur, hvis det skal være det
	if ((signatureString.length == 0) ||
	    ((signatureString.length == 1) && (signatureString != "0")) )
		return false;
	else
		return true;
}

function isInt(intString) {
	var pattern = new RegExp('^[0-9]+$');
    return pattern.test(intString);  // returns a boolean
 }
 
 function isDate(dateString) {
	var regEx = /^\d{4}-\d{2}-\d{2}$/;
	if(!dateString.match(regEx))
		return false;  // Invalid format
	var d;
	if(!((d = new Date(dateString))|0))
		return false; // Invalid date (or this could be epoch)
	return d.toISOString().slice(0,10) == dateString;
 }
 
 function isTime(timeString) {
	var pattern = new RegExp('^(?:2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]$');
    return pattern.test(timeString);  // returns a boolean
 }
 
 function isDecimal(decimalString) {
	var pattern = new RegExp('^-?[0-9]+[.]([0-9]{2})?$');
	//if (decimalString.includes(","))
	//	return false;
    return pattern.test(decimalString);  // returns a boolean
 }
 
 function is512bit(b64String) {
	// 128 bytes = 512 bits
	return (b64String.toString(16).length == 128);
 }

 function is1024bit(b64String) {
	// 256 bytes = 1024 bits
	return (b64String.toString(16).length == 256);
 }

/***********************************************
* Metode: RSA-SHA1-1024
************************************************/
function RSA_SHA1(txt_string, privateKey, publicKey) {
	slettSignatur();

	if (!isLegalRSAPrivateKey(privateKey)) {
		alert(RSAERRPRVKEY);
		return;
	}

	// test if private key is legal base64
	try {
		var der = Base64.unarmor(privateKey);
	} catch (e) {
		alert(RSAPRVKEY + e);
		return;
    }

	// test if legal ASN1 format
	try {
		var asn1 = ASN1.decode(der);
	} catch (e) {
		alert(RSAPRVKEY + e);
		return;
    }

	if (publicKey.length == 0) {
		alert(RSAPUBKEYMISSING);
		return;
	}

	if (!isLegalRSAPublicKey(publicKey)) {
		alert(RSAERRPUBKEY);
		return;
	}

	// test if public key is legal base64
	try {
		var derp = Base64.unarmor(publicKey);
	} catch (e) {
		alert(RSAPUBKEY + e);
		return;
    }

	// test if legal ASN1 format"
	try {
		var asn1p = ASN1.decode(derp);
	} catch (e) {
		alert(RSAPUBKEY + e);
		return;
    }

	// loading private key from PEM string
	var prvKey = KEYUTIL.getKey(privateKey);
	var prvModulus = prvKey.n; //get modulus
	var prvModLength = prvModulus.toString(16).length;
	var d = prvKey.d; // private exponent
	var e = prvKey.e; // public exponent, usually 65537 (0x010001)
	var p = prvKey.p; // prime 1
	var q = prvKey.q; // prime 2
	var dBitLength = d.toString(2).length;
	var nBitLength = prvModulus.toString(2).length;
	
	if (!is1024bit(prvModulus)) {
		alert(RSAPRVKEYNOT1024);
		return;
	}
	
	if (!is1024bit(d) && !is512bit(e) && !is512bit(p) && !is512bit(q)) {
		alert(RSAERRPRVKEYLENGTH);
		return;
	}
	
	// public exponent should be 65537 (0x010001)
	if (prvKey.e != 65537) {
		alert(RSAPRVKEYEXPNOT65537);
		// Fjerner kravet, men opprettholder en melding
		//return;
	}
	
	// private exponent < modulus
	if (dBitLength >= nBitLength) {
		if ((dBitLength == nBitLength) &&
		    (prvKey.d.toString(2) > prvKey.n.toString(2))) {
			alert(RSAPRVKEYEXPBIG);
			return;
		}
	}
	
	// loading public key from PEM string
	var pubKey = KEYUTIL.getKey(publicKey);
	var pubModulus = pubKey.n;

	if (!is1024bit(pubModulus)) {
		alert(RSAPUBKEYNOT1024);
		return;
	}
	
	// public exponent should be 65537 (0x010001)
	if (pubKey.e != 65537) {
		alert(RSAPUBKEYEXPNOT65537);
		// Fjerner kravet, men opprettholder en melding
		//return;
	}
	
	// private and public key match
	if (!((prvKey.n - pubKey.n) == 0) &&  // private and public modulus should be equal
	      (prvKey.e - pubKey.e) == 0) {   // private and public exponent should be equal
		alert(RSAPRVDIFFPUB);
		return;
	}

	// RSA signature generation
	var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
	sig.init(privateKey);
	sig.updateString(txt_string);
	var hSigVal = sig.sign();
	document.getElementById('signature').value = linebrk(hex2b64(hSigVal), 64);
	
	// RSA signature validation
	var sig2 = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
	sig2.init(publicKey);
	sig2.updateString(txt_string);
	var isValid = sig2.verify(hSigVal);
	
	if (!isValid)
		alert(RSAERRSIGNATURE);
}


/***********************************************
* Metode: Verify Signature
************************************************/
function verifySignature() {
	var txt_string = document.getElementById('text').value;       // gets data from input text
	var publicKey = document.getElementById('publicKey').value;   // gets data from input publicKey
	var sign_string = document.getElementById('signature').value; // gets data from signature
	var sign_string_CRS = document.getElementById('signatureCRS').value; // gets data from input CRS signature
	
	if (txt_string.length == 0) {
		alert(INGENDATA);
		return false;
	}

	if (sign_string.length == 0) {
		alert(NOSIGNATURE);
		return;
	}
	
	if (sign_string_CRS.length == 0) {
		alert(NOCASHSIGNATURE);
		return;
	}

	var isValid = false;
	
	if (document.getElementById('metode').value == 'SHA1withRSA') {
		// Verifying RSA signature
		// loading public key from PEM string
		var pubKey = KEYUTIL.getKey(publicKey);
		var pubModulus = pubKey.n;

		if (!is1024bit(pubModulus)) {
			alert(RSAPUBKEYNOT1024);
			return;
		}
	
		// public exponent should be 65537 (0x010001)
		if (pubKey.e != 65537) {
			alert(RSAPUBKEYEXPNOT65537);
			// Fjerner kravet, men opprettholder en melding
			//return;
		}
	
		// RSA signature validation
		var sig2 = new KJUR.crypto.Signature({"alg": "SHA1withRSA"});
		sig2.init(publicKey);
		sig2.updateString(txt_string);
		var sign_string_CRS_hex = b64tohex(sign_string_CRS);

		try {
			isValid = sig2.verify(sign_string_CRS_hex);
		} catch (e) {
			alert(ERRCASHSIGNATURE + e);
			return;
		}
	} else {
		// Verifying HMAC signature
		isValid = (sign_string == sign_string_CRS);
	}
	
	if (isValid)
		alert(OKSIGNATURE);
	else
		alert(ERRSIGNATURE);
}

/***********************************************
* Metode: HMAC-SHA1-128
* Eksempel: 
* Tekst til signering: 0;2016-11-24;10:39:00;2;1.00;0.96
* Nøkkel: SkatteetatenSign
* Signatur: iHh68DWCU3G42eL/7vOGUMSkvMM=
************************************************/
function HMAC_SHA1(txt_string, privateKey) {
	var keyType = "TEXT";

	slettSignatur();
	document.getElementById('secretKey').value = "";

	// 24 bytes kan bety at base64 er brukt
	if (privateKey.length == 24) {
		// test if private key is legal base64
		if (!isBase64(privateKey)) {
			alert(HMACKEYERR);
			return;
		}
		
		keyType = "B64";
	} else {
		// Forutsetter at nøkkelen er TEXT hvis den ikke er Base64
		// 16 bytes = 128 bits
		if (privateKey.length != 16) {
			alert(HMACKEYNOT128);
			return;
		}
	}

	if (keyType == "TEXT") {
		document.getElementById('secretKey').value = linebrk(utf8tob64(privateKey), 64);
	} else {
		document.getElementById('secretKey').value = privateKey;
	}		

	try {
		var hmacObj = new jsSHA("SHA-1", "TEXT");
		hmacObj.setHMACKey(privateKey, keyType)
		hmacObj.update(txt_string);
		var sign = hmacObj.getHMAC("B64");
	} catch (e) {
		alert(e);
	//return;
	}
		
	document.getElementById('signature').value = sign;
	if (!isSignature(sign)) {
		alert(HMACERRSIGNATURE);
	};
}


/***********************************************
* Check if string is legal base 64 encoded
************************************************/
function isBase64(str) {
  const notBase64 = /[^A-Z0-9+\/=]/i;
  const len = str.length;
  if (!len || len % 4 !== 0 || notBase64.test(str)) {
    return false;
  }
  const firstPaddingChar = str.indexOf('=');
  return firstPaddingChar === -1 ||
    firstPaddingChar === len - 1 ||
    (firstPaddingChar === len - 2 && str[len - 1] === '=');
}

/***********************************************
* Initialiserer comboboks
************************************************/
function init() {
   //Setter opp valgmuligheter for signeringsmetode
   makeMethodOptions();
   makeLanguageOptions();
   makeNewLables();
}

/***********************************************
* Slett signaturfeltet
************************************************/
function slettSignatur() {
	document.getElementById('signature').value = "";
	document.getElementById('signatureCRS').value = "";
}
	
/***********************************************
* Slett alle feltet
************************************************/
function slettAlleFelt() {
	document.getElementById('signature').value = "";
	document.getElementById('signatureCRS').value = "";
	document.getElementById('text').value = "";
	document.getElementById('privateKey').value = "";
	document.getElementById('publicKey').value = "";
	document.getElementById('secretKey').value = "";
}
	
/***********************************************
* Setter opp valgmulighetene
* i language comboboks
************************************************/
function makeLanguageOptions(){
   var language = document.forms[0].language;
   language.options.length=0;
   language.options[0]=new Option("Bokmål","nb");
   language.options[1]=new Option("English","en");
}

/***********************************************
* Setter opp valgmulighetene
* i metode comboboks
************************************************/
function makeMethodOptions(){
   var metode = document.forms[0].metode;
   metode.options.length=0;
   metode.options[0]=new Option("RSA","SHA1withRSA");
   metode.options[1]=new Option("HMAC","HmacSHA1");
}

/***********************************************
* Forandrer synlighet til et StyleObjekt
*
************************************************/
function changeObjectVisibility(objectId, newVisibility) {
	var styleObject = document.getElementById(objectId).style;
	if (styleObject) {
		styleObject.visibility = newVisibility;
		return true
	} else {
		// we couldn't find the object, so we can't change its visibility
		return false
	}
}

function changeObjectValue(objectId, newValue) {
	var HTMLObject = document.getElementById(objectId);
	if (HTMLObject) {
		HTMLObject.innerHTML = newValue;
		return true
	} else {
		// we couldn't find the object, so we can't change its value
		return false
	}
}

function changeObjectDisplay(objectId, newVisibility) {
	var styleObject = document.getElementById(objectId).style;
	if (styleObject) {
		styleObject.display = newVisibility;
		return true
	} else {
		// we couldn't find the object, so we can't change its visibility
		return false
	}
}

function showHelp() {
	if (helpVisibility == "flex") {
		helpVisibility = "none"
		document.getElementById("btn_hjelp").innerHTML = SHOWUSERSGUIDE;
	} else {
		helpVisibility = "flex";
		document.getElementById("btn_hjelp").innerHTML = HIDEUSERSGUIDE;
	}
		
	changeObjectDisplay("hjelp",helpVisibility);
}

function makeNewLables() {

	var VERSION = "(v 1.0)";
	var HELPIKON = " <img src='formula-help.png' alt='Hjelp'>";

	switch (document.getElementById('language').value) {
	case 'en':
		HELPIKON = " <img src='formula-help.png' alt='Help'>";
		// Diverse info-/feilmeldinger
		// Headingen
		document.getElementById("header").innerHTML = "Validator for digital cash register systems "+VERSION;
		// Ingressen
		document.getElementById("ingress").innerHTML = 
		"<p>This validator is intended to aid in implementing digital signatures in cash register systems according to the document <a href='http://skatteetaten.no/globalassets/standardformat-regnskapsaf-t/requirements-and-guidelines-for-implementing-digital-signatures-in-cash-register-systems.pdf' target='_blank'>Requirements and guidelines for implementing digital signatures in Cash Register Systems</a>.</p>" +
		"<p>The signing methods to be used are RSA-SHA1-1024 or HMAC-SHA1-128. The validator generates a signature based on chosen signing method, data to be signed and key(s). This signature can then be verified with the signature generated in the cash register system.</p>";
		// Brukerveiledning
	    document.getElementById("guide").innerHTML = 
		"<p>First, choose signing method: RSA or HMAC.</p>" +
		"<strong>RSA:</strong>" +
		"<ul><li>Both 'Private key' and 'Public key' must be filled out to generate an RSA signature." +
		"<li>Then you can fill out the 'Signature from cash register' to verify this.</ul>" +
		"<strong>HMAC:</strong>" +
		"<ul><li>'Secret key' must be filled out to generate the HMAC signature." +
		"<li>The secret key is also converted to base64 format (if written in text format) for use when submitting the product declaration in Altinn." +
		"<li>Then you can fill out 'Signature from cash register' to verify this.</ul>" +
		"Click on the <strong>?</strong> to see description for a particular field.";
		// genererSignatur
		PRVKEYMISSING = "Private key is missing!";
		SECKEYMISSING = "Secret key is missing!";
		// tekstTilSigneringOK
		TXTINPUT 		 = "Data for signing: ";
		ERRLENGTH 		 = "Error in format!";
		ERRSIGNATURE 	 = "Error in <signature> from last receipt!";
		ERRTRANSDATEOK 	 = "Error in transaction date <transDate>!";
		ERRTRANSTIMEOK 	 = "Error in transaction time <transTime>!";
		ERRNROK 		 = "Error in transaction number <nr>!";
		ERRTRANSAMNTINOK = "Error in amount with vat <transAmntIn>!";
		ERRTRANSAMNTEXOK = "Error in amount without vat <transAmntEx>!";
		// RSA_SHA1
		RSAERRPRVKEY         = "Error in RSA private key!";
		RSAPRVKEY            = "Private key: ";
		RSAPUBKEYMISSING     = "Public key missing!";
		RSAERRPUBKEY         = "Error in public key!";
		RSAPUBKEY            = "Public key: ";
		RSAPRVKEYNOT1024     = "RSA private key is not 1024 bits!";
		RSAERRPRVKEYLENGTH   = "RSA private key has wrong length for some elements!";
		RSAPRVKEYEXPNOT65537 = "RSA private key's 'public exponent' is not 65537 as recommended.";
		RSAPRVKEYEXPBIG      = "RSA private key's 'private exponent' is too big!";
		RSAPUBKEYNOT1024     = "RSA public key is not 1024 bits!";
		RSAPUBKEYEXPNOT65537 = "RSA public key's 'public exponent' is not 65537 as recommended.";
		RSAPRVDIFFPUB        = "RSA pPrivate key does not match public key!";
		RSAERRSIGNATURE      = "RSA error in generating signature!";
		// verifySignature
		NOSIGNATURE      = "Signature is not generated!";
		NOCASHSIGNATURE  = "Cash register signature is missing!";
		ERRCASHSIGNATURE = "Error in cash register signature: ";
		OKSIGNATURE      = "Signature is OK!";
		ERRSIGNATURE     = "Signature is WRONG!";
		// HMAC_SHA1
		HMACKEYERR       = "HMAC error in security key!";
		HMACKEYNOT128    = "HMAC security key is not 128 bits!";
		HMACERRSIGNATURE = "HMAC error in generating signature!";
		// flere steder
		HELPIKON = " <img src='formula-help.png' alt='Question'>";
		INGENDATA = "No data for signing!";
		// help button
		SHOWUSERSGUIDE = "Show Users Guide";
		HIDEUSERSGUIDE = "Hide Users Guide";
		
		// Labels
		document.getElementById("lbl_signeringsmetode").innerHTML = "Signing method";
		document.getElementById("lbl_data").innerHTML = "Data for signing"+HELPIKON;
		document.getElementById("lbl_signatur").innerHTML = "Signature"+HELPIKON;
		document.getElementById("lbl_signatur_kassa").innerHTML = "Signature from cash register"+HELPIKON;
		
		// Buttons
		if (helpVisibility == "flex")
			document.getElementById("btn_hjelp").innerHTML = HIDEUSERSGUIDE
		else
			document.getElementById("btn_hjelp").innerHTML = SHOWUSERSGUIDE;
		document.getElementById("signatur_button").innerHTML = "Generate signature";
		document.getElementById("verify_button").innerHTML = "Verify signature";
		
		// Tooltips
		document.getElementById("lbl_signatur").title = "Signature to follow the SAF-T Cash Register XML export in <br/>auditfile>company>location>cashregister>cashtransaction>signature&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
		document.getElementById("lbl_signatur_kassa").title = "Paste the signature from the cash register and click on [Verify signature].&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
		if (document.getElementById('metode').value == 'SHA1withRSA') {
			//alert("RSA engelsk");
			
			// Showing correct fields
			changeObjectDisplay("row_rsaoffentlig","flex");
			changeObjectDisplay("row_hmacsikkerhet","none");
		
			// Labels
			document.getElementById("lbl_privat").innerHTML = "Private key"+HELPIKON;
			document.getElementById("lbl_offentlig").innerHTML = "Public key"+HELPIKON;
		
			// Tooltips
			document.getElementById("lbl_data").title = 
			"The following format must be used:<br/>" +
			"«signature»;« transDate»;«transTime» ;«nr»;«transAmntIn»;«transAmntEx»<br/>" + 
			"Example: <br/>0;2014-01-24;23:59:59;123456789;1250.00;1000.00<br/>" + 
			"See section 2.2.4 in the document Requirements and guidelines for implementing digital signatures in Cash Register Systems.";
			document.getElementById("lbl_privat").title = "Private key in PEM format (base64).";
			document.getElementById("lbl_offentlig").title = "Public key in PEM format (base64).&nbsp;&nbsp;&nbsp;&nbsp;";		
		} else {
			//alert("HMAC engelsk");
			// Showing correct fields
			changeObjectDisplay("row_rsaoffentlig","none");
			changeObjectDisplay("row_hmacsikkerhet","flex");
		
			// Labels
			document.getElementById("lbl_privat").innerHTML = "Secret key"+HELPIKON;
			document.getElementById("lbl_sikkerhet").innerHTML = "Secret key for product declaration"+HELPIKON;
		
			// Tooltips
			document.getElementById("lbl_data").title = 
			"The following format should be used:<br/>" +
			"«signature»;« transDate»;«transTime» ;«nr»;«transAmntIn»;«transAmntEx»<br/>" + 
			"Example: <br/>0;2014-01-24;23:59:59;123456789;1250.00;1000.00<br/>" + 
			"See section 2.3.3 in the document Requirements and guidelines for implementing digital signatures in Cash Register Systems.";
			document.getElementById("lbl_privat").title = "Secret key in text or base64 format."; //Triks for å overskrive tegn fra RSA
			document.getElementById("lbl_sikkerhet").title = "Secret key in base64 format to be used in the product declaration (form RF-1348) in Altinn.";
		}
		break;
	case 'nb':
	default:
		HELPIKON = " <img src='formula-help.png' alt='Hjelp'>";
		// Diverse info-/feilmeldinger
		// Headingen
		document.getElementById("header").innerHTML = "Validator for digital signatur i kassasystemer "+VERSION;
		// Ingressen
		document.getElementById("ingress").innerHTML = 
		"<p>Denne validatoren er utarbeidet som et hjelpemiddel for å implementere digital signatur i kassasystemer i henhold til spesifikasjonene i dokumentet <a href='http://skatteetaten.no/globalassets/standardformat-regnskapsaf-t/requirements-and-guidelines-for-implementing-digital-signatures-in-cash-register-systems.pdf' target='_blank'>krav og retningslinjer for implementering av digital signatur for transaksjoner i kassasystemer</a>.</p>" +
		"<p>De tillatte signeringsmetodene er RSA-SHA1-1024 eller HMAC-SHA1-128. Validatoren genererer en signatur basert på valgt signeringsmetode, data som skal signeres og nøkkel/nøkkelpar. Denne signaturen kan så verifiseres mot signaturen generert i kassasystemet.</p>";
		// Brukerveiledning
		document.getElementById("guide").innerHTML = 
		"<p>Velg først hvilken signeringsmetode som skal benyttes, RSA eller HMAC.</p>" +
		"<strong>RSA:</strong>" +
		"<ul><li>Både 'Privat nøkkel' og 'Offentlig nøkkel' må fylles ut for å generere RSA signatur." +
		"<li>Deretter kan 'Signatur fra kassasystem' fylles ut for å verifisere denne.</ul>" +
		"<strong>HMAC:</strong>" +
		"<ul><li>'Hemmelig nøkkel' må fylles ut for å generere HMAC signatur." +
		"<li>Den hemmelige nøkkelen konverteres samtidig til base64 format (hvis den var i tekstformat) som kan brukes ved innsendelse av produkterklæringen i Altinn." +
		"<li>Deretter kan 'Signatur fra kassasystem' fylles ut for å verifisere denne.</ul>" +
		"<p>Klikk på <strong>?</strong> for å få beskrivelse på et spesifikt felt.</p>";
		// genererSignatur
		PRVKEYMISSING = "Privat nøkkel mangler!";
		SECKEYMISSING = "Hemmelig nøkkel mangler!";
		// tekstTilSigneringOK
		TXTINPUT 		 = "Data til signering: ";
		ERRLENGTH 		 = "Feil format!";
		ERRSIGNATURE 	 = "Feil i <signature> fra forrige kvittering!";
		ERRTRANSDATEOK 	 = "Feil i transaksjonsdato <transDate>!";
		ERRTRANSTIMEOK 	 = "Feil i transaksjonsklokkeslett <transTime>!";
		ERRNROK 		 = "Feil i transaksjonsnummer <nr>!";
		ERRTRANSAMNTINOK = "Feil i beløp med mva <transAmntIn>!";
		ERRTRANSAMNTEXOK = "Feil i beløp uten mva <transAmntEx>!";
		// RSA_SHA1
		RSAERRPRVKEY         = "Feil i privat nøkkel for RSA!";
		RSAPRVKEY            = "Nøkkel privat: ";
		RSAPUBKEYMISSING     = "Offentlig nøkkel mangler!";
		RSAERRPUBKEY         = "Feil i offentlig nøkkel!";
		RSAPUBKEY            = "Offentlig nøkkel: ";
		RSAPRVKEYNOT1024     = "RSA privat nøkkel er ikke 1024 bits!";
		RSAERRPRVKEYLENGTH   = "RSA privat nøkkel har feil lengde på noen elementer!";
		RSAPRVKEYEXPNOT65537 = "RSA privat nøkkel sin 'public exponent' er ikke 65537 som anbefalt.";
		RSAPRVKEYEXPBIG      = "RSA privat nøkkel sin 'private exponent' er for stor!";
		RSAPUBKEYNOT1024     = "RSA offentlig nøkkel er ikke 1024 bits!";
		RSAPUBKEYEXPNOT65537 = "RSA offentlig nøkkel sin 'public exponent' er ikke 65537 som anbefalt.";
		RSAPRVDIFFPUB        = "RSA privat og offentlig nøkkel passer ikke sammen!";
		RSAERRSIGNATURE      = "RSA feil i generering av signatur!";
		// verifySignature
		NOSIGNATURE      = "Signatur ikke generert!";
		NOCASHSIGNATURE  = "Signatur fra kassasystemet mangler!";
		ERRCASHSIGNATURE = "Feil i signatur fra kassasystemet: ";
		OKSIGNATURE      = "Signaturen er OK!";
		ERRSIGNATURE     = "Signaturen er FEIL!";
		// HMAC_SHA1
		HMACKEYERR       = "HMAC feil i hemmelig nøkkel!";
		HMACKEYNOT128    = "HMAC hemmelig nøkkel er ikke 128 bits!";
		HMACERRSIGNATURE = "HMAC feil i generering av signatur!";
		// flere steder
		INGENDATA = "Ingen data til signering!";
		HELPIKON = " <img src='formula-help.png' alt='Spørsmål'>";
		// help button
		SHOWUSERSGUIDE = "Vis bruksanvisning";
		HIDEUSERSGUIDE = "Gjem bruksanvisning";
		
		// Labels
		document.getElementById("lbl_signeringsmetode").innerHTML = "Signeringsmetode";
		document.getElementById("lbl_data").innerHTML = "Data til signering"+HELPIKON;
		document.getElementById("lbl_signatur").innerHTML = "Signatur"+HELPIKON;
		document.getElementById("lbl_signatur_kassa").innerHTML = "Signatur fra kassasystem"+HELPIKON;

		// Buttons
		if (helpVisibility == "flex")
			document.getElementById("btn_hjelp").innerHTML = HIDEUSERSGUIDE
		else
			document.getElementById("btn_hjelp").innerHTML = SHOWUSERSGUIDE;
		document.getElementById("signatur_button").innerHTML = "Generer signatur";
		document.getElementById("verify_button").innerHTML = "Verifiser signatur";
		
		// Tooltips
		document.getElementById("lbl_signatur").title = "Signaturen som skal følge med i SAF-T Cash Register XML eksport under <br/>auditfile>company>location>cashregister>cashtransaction>signature";
		document.getElementById("lbl_signatur_kassa").title = "Her legger du inn signaturen fra kassasystemet og klikker på [Verifiser signatur].";
		
		if (document.getElementById('metode').value == 'SHA1withRSA') {
			//alert("RSA");
			// Showing correct fields
			changeObjectDisplay("row_rsaoffentlig","flex");
			changeObjectDisplay("row_hmacsikkerhet","none");
		
			// Labels
			document.getElementById("lbl_privat").innerHTML = "Privat nøkkel"+HELPIKON;
			document.getElementById("lbl_offentlig").innerHTML = "Offentlig nøkkel"+HELPIKON;
		
			// Tooltips
			document.getElementById("lbl_data").title = 
			"Følgende format skal benyttes:<br/>" +
			"«signature»;« transDate»;«transTime» ;«nr»;«transAmntIn»;«transAmntEx»<br/>" + 
			"For eksempel: <br/>0;2014-01-24;23:59:59;123456789;1250.00;1000.00<br/>" + 
			"Se punkt 2.2.4 i dokumentet krav og retningslinjer for implementering av digital signatur for transaksjoner i kassasystemer.&nbsp;&nbsp;&nbsp;&nbsp;";
			document.getElementById("lbl_privat").title = "Privat nøkkel i PEM format (base64).&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
			document.getElementById("lbl_offentlig").title = "Offentlig nøkkel i PEM format (base64).";		
		} else {
			//alert("HMAC");
			// Showing correct fields
			changeObjectDisplay("row_rsaoffentlig","none");
			changeObjectDisplay("row_hmacsikkerhet","flex");
		
			// Labels
			document.getElementById("lbl_privat").innerHTML = "Hemmelig nøkkel"+HELPIKON;
			document.getElementById("lbl_sikkerhet").innerHTML = "Sikkerhetsnøkkel ved produkterklæring"+HELPIKON;
		
			// Tooltips
			document.getElementById("lbl_data").title = 
			"Følgende format skal benyttes:<br/>" +
			"«signature»;« transDate»;«transTime» ;«nr»;«transAmntIn»;«transAmntEx»<br/>" + 
			"For eksempel: <br/>0;2014-01-24;23:59:59;123456789;1250.00;1000.00<br/>" + 
			"Se punkt 2.3.3 i dokumentet krav og retningslinjer for implementering av digital signatur for transaksjoner i kassasystemer.";
			document.getElementById("lbl_privat").title = "Hemmelig nøkkel i tekst eller base64 format.";
			document.getElementById("lbl_sikkerhet").title = "Hemmelig nøkkel i base64 format til bruk ved produkterklæring (skjema RF-1348) i Altinn.";
		}
	}
	
	// Have to initiate tooltip again after changing titles
	<!-- Tipped - A Complete Javascript Tooltip Solution -->
	Tipped.create('.tooltip', { 
		position: 'righttop',
		behavior: 'sticky',
		showOn: 'click',
		size: 'large'
 	});
}
