function urlencode(obj) {
  var str = [];
  for(var p in obj)
    if (obj.hasOwnProperty(p)) {
      str.push(encodeURIComponent(p) + "=" + encodeURIComponent(obj[p]));
    }
  return str.join("&");
}
function ajaxPost(url, data, success, fail) {
    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function() {
        if (XMLHttpRequest.DONE != xhr.readyState) { return; }
        var response = JSON.parse(xhr.responseText);
        if (xhr.status === 200) {
            if (success) { success(response); }
        }
        else {
            console.log(response, xhr.responseText);
            if (fail) { fail(response); }
        }
    }
    xhr.open('POST', url);
    xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    xhr.send(urlencode(data));
}
function showPress() {
    document.getElementById('press').style.display = 'block';
}
function hidePress() {
    document.getElementById('press').style.display = 'none';
}
displayResponse = function(resp) {
    document.getElementById('ajax-response').innerHTML = JSON.stringify(resp);
};
showAuthError = function(code) {
    // https://developers.yubico.com/U2F/Libraries/Client_error_codes.html
    switch (code) {
    case 1:
        message = 'other error';
        break;
    case 2:
        message = 'bad request';
        break;
    case 3:
        message = 'unsupported client configuration';
        break;
    case 4:
        message = 'ineligible request';
        break;
    case 5:
        message = 'timeout';
        break;
    }
    alert(message);
};

document.getElementById('debug').addEventListener('change', function(e) {
    box = document.getElementById('debug');
    if (box.checked) {
        document.body.setAttribute('class', 'debug');
    } else {
        document.body.setAttribute('class', '');
    }
});

document.getElementById('register').addEventListener("submit", function(e) {
    e.preventDefault();
    var username = document.getElementById("reg_username").value;
    var password = document.getElementById("reg_password").value;
    ajaxPost('/register_user.php', {"username":username, "password":password}, displayResponse);
});

document.getElementById('login').addEventListener("submit", function(e) {
    e.preventDefault();
    var username = document.getElementById("login_username").value;
    var password = document.getElementById("login_password").value;
    ajaxPost('/login_user.php', {"username":username, "password":password}, displayResponse);
});
document.getElementById('register_token').addEventListener("submit", function(e) {
    e.preventDefault();
    ajaxPost('/u2f_register_data.php', {}, function(resp) {
        document.getElementById('reg_request_to_sign').value = JSON.stringify(resp.request) + "\n" + JSON.stringify(resp.signatures);
        showPress();
        u2f.register([resp.request], resp.signatures, function(sig) {
            hidePress();
            if (sig.errorCode) { showAuthError(sig.errorCode); return; }
            document.getElementById('reg_signature').value = JSON.stringify(sig);
            // actually submit stuff now
            ajaxPost('/complete_registration.php', {
                "signature_str": JSON.stringify(sig)
            }, displayResponse, displayResponse);
        });
    }, null);
});

document.getElementById('auth_form').addEventListener("submit", function(e) {
    e.preventDefault();
    ajaxPost('/u2f_auth_data.php', {}, function(resp) {
        document.getElementById("auth_request_to_sign").value = JSON.stringify(resp);
        showPress();
        u2f.sign(resp, function(sig) {
            hidePress();
            if (sig.errorCode) { showAuthError(sig.errorCode); return; }
            document.getElementById("auth_signature").value = JSON.stringify(sig);
            // Do auth POST
            ajaxPost('/complete_auth.php', {
                "signature_str": JSON.stringify(sig)
            }, displayResponse, displayResponse);
        });
    }, displayResponse);
});
 
