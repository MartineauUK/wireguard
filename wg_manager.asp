<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<meta http-equiv="X-UA-Compatible" content="IE=Edge"/>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<meta HTTP-EQUIV="Pragma" CONTENT="no-cache">
<meta HTTP-EQUIV="Expires" CONTENT="-1">
<link rel="shortcut icon" href="images/favicon.png">
<link rel="icon" href="images/favicon.png">
<title><#833#> - WireGuard® Client</title>
<link rel="stylesheet" href="index_style.css">
<link rel="stylesheet" href="form_style.css">

<style>
p{
font-weight: bolder;
}
.collapsible {
  color: white;
  padding: 0px;
  width: 100%;
  border: none;
  text-align: left;
  outline: none;
  cursor: pointer;
}
</style>
<!--<script src="/js/jquery.js"></script>-->
<script language="JavaScript" type="text/javascript" src="/state.js"></script>
<script language="JavaScript" type="text/javascript" src="/general.js"></script>
<script language="JavaScript" type="text/javascript" src="/popup.js"></script>
<script language="JavaScript" type="text/javascript" src="/help.js"></script>
<script language="JavaScript" type="text/javascript" src="/validator.js"></script>
<script language="JavaScript" type="text/javascript" src="/client_function.js"></script>
<script language="JavaScript" type="text/javascript" type="text/javascript" src="/form.js"></script>
<script language="JavaScript" type="text/javascript" src="js/httpApi.js"></script>
<script language="JavaScript" type="text/javascript" src="js/qrcode.min.js"></script>
<script language="JavaScript" type="text/javascript" src="js/jquery.js"></script>
<!--<script language="JavaScript" type="text/javascript" src="/ext/shared-jy/jquery.js"></script>-->

<script language="JavaScript" type="text/javascript" src="/ext/wireguard/ExecuteResults.js"></script>
<!--<script language="JavaScript" type="text/javascript" src="/ext/wireguard/ExecutedTS.js"></script>-->
<style>
#wgm_QRCode_block{
position: absolute;
width: 230px;
height: 260px;
background-color: #444f53;
padding: 3px 3px;
margin-top: -40px;
}
</style>
<!-- https://www.w3schools.com/howto/tryit.asp?filename=tryhow_css_tooltip-->
<style>
.tooltip {
  position: relative;
  display: inline-block;
  border-bottom: 1px dotted black;
}

.tooltip .tooltiptext {
  visibility: hidden;
  width: 230px;
  background-color: #4D595D;
  color: #fff;
  text-align: center;
  border-radius: 6px;
  padding: 5px 0;
  position: absolute;
  z-index: 1;
  bottom: 125%;
  left: 50%;
  margin-left: -60px;
  opacity: 0;
  transition: opacity 0.3s;
}

.tooltip .tooltiptext::after {
  content: "";
  position: absolute;
  top: 100%;
  left: 50%;
  margin-left: -5px;
  border-width: 5px;
  border-style: solid;
  border-color: #4D595D transparent transparent transparent;
}

.tooltip:hover .tooltiptext {
  visibility: visible;
  opacity: 1;
}
</style>
<script>
<% get_wgc_parameter(); %>
var custom_settings = <% get_custom_settings(); %>;

var wgcindex = "<% nvram_get("wgmc_unit"); %>";

window.onresize = function() {
cal_panel_block("wgm_QRCode_block", 0.18);
}
function initial(){
    show_menu();

    /* As per RMerlin Wiki https://github.com/RMerl/asuswrt-merlin.ng/wiki/Addons-API */
    if (custom_settings.wgm_version == undefined)
            document.getElementById('wgm_version').value = "N/A";
    else
            document.getElementById('wgm_version').value = custom_settings.wgm_version;

    if (custom_settings.wgm_Kernel == undefined)
            document.getElementById('wgm_Kernel').value = "N/A";
    else
            document.getElementById('wgm_Kernel').value = custom_settings.wgm_Kernel;

    if (document.getElementById("wgm_ExecuteResultsBase64").innerHTML == "Pending............") {
        UpdateResults();

        document.getElementById("wgm_ExecuteResultsBase64").innerHTML == "Ready"
        }

    if (custom_settings.wgm_Execute_Result == undefined)
            document.getElementById("wgm_ExecuteResultsBase64").innerHTML = "N/A"
    else
           document.getElementById("wgm_ExecuteResultsBase64").innerHTML = atob(custom_settings.wgm_Execute_Result);

    GetConfigSettings();

    document.getElementById('wgm_WebUI_Import').textContent = ""

    $("thead").click(function(){
        $(this).siblings().toggle("fast");
    })

    $(".default-collapsed").trigger("click");
}
function UpdateResults(){

    document.getElementById("wgm_ExecuteResultsBase64").innerHTML = atob(custom_settings.wgm_Execute_Result);

    document.getElementById("wgm_ExecuteRC").innerHTML =    custom_settings.wgm_ExecuteRC;
    /*ShowExecutedTS();*/
    /*ShowExecuteResults();*/
}
function CMDExecute(){

HideCMDRC();
   ShowCMDEexecuting();


   /* As per RMerlin Wiki https://github.com/RMerl/asuswrt-merlin.ng/wiki/Addons-API */
   /* Retrieve value from input fields, and store in object */
   custom_settings.wgm_Execute = document.getElementById('wgm_Execute').value;
   custom_settings.wgm_ExecuteRC = "Pending.....";

   /* Store object as a string in the amng_custom hidden input field */
   document.getElementById('amng_custom').value = JSON.stringify(custom_settings);

    if(validForm()){

        debugger;

        if (custom_settings.wgm_Execute == "stop" || custom_settings.wgm_Execute == "start") {
            /*document.action_wait.value = "3"; */
            showLoading();
            }

        /*alert("Confirmation prompts such as\n\t\t'Are you sure you want to DELETE a Peer?\nobviously cannot be manually answered, so an affirmative auto reply\n\t\t'Y'\nwill be used'.\n\nSimilarly if you create a new Road-Warrior 'device' Peer, the Parent 'server' Peer will be automatically restarted so it can listen for the new Road-Warrior 'device' Peer, which may interrupt other Road-Warrior 'device' connections");*/

        document.form.submit();

        /*sleepThenAct();*/

        UpdateResults();
    }
}
function CMDExecuteARG(command){

    ShowCMDEexecuting();

    custom_settings.wgm_Execute = command;
    custom_settings.wgm_ExecuteRC = "Pending.....";

   /* Store object as a string in the amng_custom hidden input field */
   document.getElementById('amng_custom').value = JSON.stringify(custom_settings);

    if(validForm()){

        if (custom_settings.wgm_Execute == "stop" || custom_settings.wgm_Execute == "start") {
            /*document.action_wait.value = "3";*/
            showLoading();
            }

        document.form.submit();

        /*sleepThenAct();*/

        UpdateResults();
    }
}
function CMDExecutePeerImport(command){

    ShowCMDEexecuting();
    custom_settings.wgm_ExecuteRC = "Pending.....";

	var importType="";
	
	if (document.getElementById('wgm_ImportServer_enabled').checked) {
		importType="type=server"
	}

    if (document.getElementById('wgm_WebUI_Import').textContent == undefined)
        custom_settings.wgm_Execute = "import " + document.getElementById('wgm_PeerImport').value + " " + importType;
    else
        custom_settings.wgm_Execute = "WebUI_Import " + btoa(document.getElementById('wgm_WebUI_Import').textContent + " " + importType);

   /* Store object as a string in the amng_custom hidden input field */
   document.getElementById('amng_custom').value = JSON.stringify(custom_settings);

    if(validForm()){
        showLoading();
        document.form.submit();

        /*sleepThenAct();*/

        UpdateResults();
    }
    document.getElementById('wgm_WebUI_Import').textContent = ""
}
function SwitchStatus(){
	
	Connected = "<% nvram_get("wgmc_enable"); %>"
	
	if (Connected == "1") {
		CMDExecuteARG("stop wg1" + <% nvram_get("wgmc_unit"); %>);
	} else {
		CMDExecuteARG("start wg1" + <% nvram_get("wgmc_unit"); %>);
	}
	
}
function applyRule(){

    if(validForm()){
        /*showLoading();*/
        document.form.submit();
    }
}
function validForm(){

    return true;
}
function sleepFor(sleepDuration){
    var now = new Date().getTime();
    while(new Date().getTime() < now + sleepDuration){
        /* Do nothing */
    }
}
function sleepThenAct(){
    sleepFor(2000);
    console.log("Hello, JavaScript sleep!");
}
function change_wgmc_unit(unit){
document.chg_wgmc.wgmc_unit.value=unit.toString();
CMDExecuteARG('export wg1' + unit);
// document.chg_wgmc.submit();

}
function ShowQRCode() {
$('#wgm_QRCode_block').show();
cal_panel_block("wgm_QRCode_block", 0.18);
}
function HideQRCode(){
$('#wgm_QRCode_block').hide();
}
function ShowCMDEexecuting() {
$('#imgExecuting').show();
/*document.getElementById("imgExecuting").style.visibility = "visible";*/
}
function HideCMDEexecuting(){
$('#imgExecuting').hide();
/*document.getElementById("imgExecuting").style.visibility = "visible";*/
}
function ShowCMDRC() {
$('#wgm_ExecuteRC').show();
/*document.getElementById("imgExecuting").style.visibility = "visible";*/
}
function HideCMDRC(){
$('#wgm_ExecuteRC').hide();
/*document.getElementById("imgExecuting").style.visibility = "visible";*/
}
function ShowWinFile() {
$('#wgm_WinFile_block').show();
cal_panel_block("wgm_WinFile_block", 0.18);
}
function HideWinFile(){
$('#wgm_WinFile_block').hide();
}

function GetConfigSettings() {
    $.ajax({
        url: "/ext/wireguard/config.htm",
        dataType: "text",
        cache: !1,
        error: function(t) {
            setTimeout(GetConfigSettings, 1e3)
        },
        success: function(data) {
            for (var configdata = data.split("\n"), configdata = configdata.filter(Boolean), i = 0; i < configdata.length; i++) {

            /*https://stackoverflow.com/questions/58718800/how-to-set-radio-button-by-default-based-on-variable-value*/
                if (configdata[i] == "WEBUI"){
                    $('#wgm_WEBUI').prop('checked',true);
                }
                if (configdata[i] == "USE_ENTWARE_KERNEL_MODULE"){
                    $('#wgm_USE_ENTWARE_KERNEL_MODULE_enabled').prop('checked',true);
                }
                if (configdata[i] == "NOIPV6"){
                    $('#wgm_NOIPV6_enabled').prop('checked',true);
                }
                if (configdata[i] == "DISABLE_FLOW_CACHE"){
                    $('#wgm_DISABLE_FLOW_CACHE_enabled').prop('checked',true);
                }
                if (configdata[i] == "NOCOLOR"){
                    $('#wgm_NOCOLOR_enabled').prop('checked',true);
                }
                if (configdata[i] == "NOMENU"){
                    $('#wgm_NOMENU_enabled').prop('checked',true);
                }
                if (configdata[i] == "ROGUE220IGNORE"){
                    $('#wgm_ROGUE220IGNORE_enabled').prop('checked',true);
                }
                if (configdata[i] == "ROGUE220DELETE"){
                    $('#wgm_ROGUE220DELETE_enabled').prop('checked',true);
                }
                if (configdata[i] == "KILLSWITCH"){
                    $('#wgm_KILLSWITCH_enabled').prop('checked',true);
                }
            }
        }
    })
}
function LetsDEBUG(wot) {
    /*alert(wot);*/
    debugger;
}

</script>
<script type="text/javascript">
// Popup window code
function newPopup(url) {
    popupWindow = window.open(
        url,'popUpWindow','height=300,width=400,left=10,top=10,resizable=yes,scrollbars=yes,toolbar=yes,menubar=no,location=no,directories=no,status=yes')
}
</script>
<script>
// https://sebhastian.com/javascript-confirmation-yes-no/
function confirmPeerDelete(wgPeer) {
	let confirmAction = confirm("Confirm OK to DELETE Peer: '" + wgPeer + "'");
	if (confirmAction) {
	  CMDExecuteARG("peer " + wgPeer + " del"); 
	} else {
	  alert("DELETE Peer: '" + wgPeer + "' request cancelled");
	}
}
</script>
<script>
function confirmDescFieldUpdate(comment) {
	let confirmAction = confirm("Confirm OK to Update 'Annotate/Tag' to " + comment + "'");
	if (confirmAction) {
	  CMDExecuteARG("peer wg1" + wgcindex + " comment " + comment);
	} else {
	  alert("Update 'Annotate/Tag' cancelled!");
	}
}
</script>
<script>
function confirmAutoFieldUpdate(auto) {
let confirmAction = confirm("Confirm OK to Update 'Auto-Start Type' to '" + auto + "'");
	if (confirmAction) {
	  CMDExecuteARG("peer wg1" + wgcindex + " auto=" + auto);
	} else {
	  alert("Update Update 'Auto-Start' cancelled!");
	}
}
</script>
<script>
function confirmAddressFieldUpdate(address) {
let confirmAction = confirm("Confirm OK to Update 'Address' to '" + address + "'");
	if (confirmAction) {
	  CMDExecuteARG("peer wg1" + wgcindex + " ip=" + address);
	} else {
	  alert("Update 'Address' cancelled!");
	}
}
</script>
<script>
function confirmDNSFieldUpdate(dns) {
let confirmAction = confirm("Confirm OK to Update 'DNS' to '" + dns + "'");
	if (confirmAction) {
	  CMDExecuteARG("peer wg1" + wgcindex + " dns=" + dns);
	} else {
	  alert("Update 'DNS' cancelled!");
	}
}
</script>
<script>
function confirmPreSharedKeyFieldUpdate(psk_value) {
let confirmAction = confirm("Confirm OK to Update 'Preshared Key' to '" + psk_value + "'");
	if (confirmAction) {
	  CMDExecuteARG("peer wg1" + wgcindex + " psk=" + psk_value);
	} else {
	  alert("Update 'Preshared Key' cancelled!");
	}
}
</script>
<script>
function confirmAllowedIPsFieldUpdate(allowedips) {
let confirmAction = confirm("Confirm OK to Update 'Allowed IPs' to '" + allowedips + "'");
	if (confirmAction) {
	  CMDExecuteARG("peer wg1" + wgcindex + " allowedips=" + allowedips);
	} else {
	  alert("Update 'Allowed IPs' cancelled!");
	}
}
</script>
<script>
function confirmEndpointAddressFieldUpdate(ep_addr) {
let confirmAction = confirm("Confirm OK to Update 'Endpoint Address' to '" + ep_addr + "'");
	if (confirmAction) {
	  CMDExecuteARG("peer wg1" + wgcindex + " endpoint=" + ep_addr + ":" + document.getElementById('wgc_ep_port').value);
	} else {
	  alert("Update 'Endpoint Address' cancelled!");
	}
}
</script>
<script>
function confirmEndpointPortFieldUpdate(epp_value) {
let confirmAction = confirm("Confirm OK to Update 'Endpoint Port' to '" + epp_value + "'");
	if (confirmAction) {
	  CMDExecuteARG("peer wg1" + wgcindex + " endpoint=" + document.getElementById('wgc_ep_addr').value + ":" + epp_value);
	} else {
	  alert("Update 'Endpoint Port' cancelled!");
	}
}
</script>
<script>
function confirmPersistentKeepAliveFieldUpdate(pka_value) {
let confirmAction = confirm("Confirm OK to Update 'Persistent Keep Alive' to '" + pka_value + "'");
	if (confirmAction) {
	  CMDExecuteARG("peer wg1" + wgcindex + " psk=" + pka_value);
	} else {
	  alert("Update 'Persistent Keep Alive' cancelled!");
	}
}
</script>
<script>
function confirmDeleteVPNDirector() {
let confirmAction = confirm("Confirm OK to DELETE ALL 'VPN Director' Policy Routing rules");
	if (confirmAction) {
	  CMDExecuteARG('vpndirector delete');
	} else {
	  alert("DELETE ALL 'VPN Director' Policy Routing rules cancelled!");
	}
}
</script>

</head>
<body onload="initial();" onunLoad="return unload_body();" class="bg">
    <div id="TopBanner"></div>
<div id="Loading" class="popup_bg"></div>
<iframe name="hidden_frame" id="hidden_frame" src="" width="0" height="0" frameborder="0"></iframe>
<form method="post" name="form" id="ruleForm" action="/start_apply.htm" target="hidden_frame">
<input type="hidden" name="productid" value="<% nvram_get("productid"); %>">
<input type="hidden" name="current_page" value="wg_manager.asp">
<input type="hidden" name="next_page" value="wg_manager.asp">
<input type="hidden" name="modified" value="0">
<input type="hidden" name="first_time" value="">
<input type="hidden" name="action_mode" value="apply">
<input type="hidden" name="action_script" value="restart_wg_manager|serviceevent">
<input type="hidden" name="action_wait" value="1">
<input type="hidden" name="preferred_lang" id="preferred_lang" value="<% nvram_get("preferred_lang"); %>">
<input type="hidden" name="firmver" value="<% nvram_get("firmver"); %>">

<input type="hidden" name="amng_custom" id="amng_custom" value="">

<table class="content" align="center" cellpadding="0" cellspacing="0">
    <tr>
        <td width="17">&nbsp;</td>
        <td valign="top" width="202">
        <div id="mainMenu"></div>
        <div id="subMenu"></div>
        </td>
        <td valign="top">
        <div id="tabMenu" class="submenuBlock"></div>
        <table width="98%" border="0" align="left" cellpadding="0" cellspacing="0">
            <tr>
                <td valign="top" >
                <table width="760px" border="0" cellpadding="4" cellspacing="0" class="FormTitle" id="FormTitle">
                    <tbody>
                        <tr>
                            <td bgcolor="#4D595D" valign="top" >
                            <div>&nbsp;</div>
                            <div class="formfonttitle">VPN - WireGuard® Manager© v1.01 by Martineau</div>
                            <div id="divSwitchMenu" style="margin-top:-40px;float:right;"></div
                            <div style="margin:10px 0 10px 5px;" class="splitLine"></div>
                            <table width="100%" border="0" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
                                    <tr>
                                        <th>WireGuard® Manager Version</th>
                                            <td>
                                                <input type="text" readonly maxlength="7" class="input_6_table" id="wgm_version">
											</td>
											<td align="center">
												<input type="button" class="button_gen"  onclick="JavaScript:newPopup('https://github.com/MartineauUK/wireguard/commits/dev/wg_manager.sh');" value="Change Log" id="btnShowHelp" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
                                            </td>
                                            <td colspan="2" align="center">
                                                <input type="button" class="button_gen" onclick="JavaScript:newPopup('/ext/wireguard/help.htm');" value="Help" id="btnShowHelp" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
                                            </td>
                                    </tr>
                                    <tr>
                                        <th>WireGuard® Kernel Module version</th>
                                            <td>
                                                <input type="text" readonly maxlength="30" class="input_12_table" id="wgm_Kernel">
                                            </td>
                                    </tr>
                            </table>

<div>&nbsp;</div>
<div class="formfonttitle">WireGuard® Manager©</div>
<table id="WgcBasicTable" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable SettingsTable">
<thead class="collapsible">
    <tr><td colspan="2">Command Interface (click to expand/collapse)</td></tr>
</thead>
<tbody>
        <!--<tr>
            <td colspan="2">WireGuard® Manager© Command</td>
        </tr>-->
        <td colspan="2" class="execbutton">
            <label>wgm </label>
            <input type="text" maxlength="100" class="input_32_table" id="wgm_Execute">
            <img id="imgExecuting" style="vertical-align: middle; display: none;" src="images/InternetScan.gif">
            <input type="button" class="button_gen" onclick="CMDExecute();" value="Execute" id="btnCMDExecute" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            <label>RC= </label>
            <input type="text" readonly maxlength="6" class="input_6_table" id="wgm_ExecuteRC">
            <input type="button" onClick="location.href=location.href" value="Refresh Results" class="button_gen" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
        </td>
        <tr>
            <td colspan="2">Command Execute Output</td>
        </tr>
        <tr>
            <td style="padding: 0px;">
            <div style="color:#FFCC00;"><input type="checkbox" checked id="auto_refresh">Auto refresh</div>

            <!--Syslog text area definition-->
            <!--<textarea cols="63" rows="27" wrap="off" readonly="readonly" id="textarea" class="textarea_ssh_table" style="width:99%; font-family:'Courier New', Courier, mono; font-size:11px;">#TOP of Syslog</textarea>-->
            <!--<textarea cols="63" rows="27" wrap="off" readonly="readonly" id="wgm_ExecuteResultsBase64" class="textarea_ssh_table" style="width:99%; font-family:'Courier New', Courier, mono; font-size:13px;">#TOP of Syslog</textarea>-->
            <textarea cols="63" rows="27" wrap="off" readonly="readonly" id="wgm_ExecuteResultsBase64" class="textarea_ssh_table" style="width:99%; font-family:'Courier New', Helvetica, MS UI Gothic, MS P Gothic, Microsoft Yahei UI, sans-serif; font-size:13px;">#TOP of Syslog</textarea>
        </tr>
</tbody>
</table>


<!--====================================================Peer Control (Import etc.)==========================================================-->
<div style="line-height:10px;">&nbsp;</div>
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#4D595D" class="FormTable">
<thead class="collapsible">
    <tr><td colspan="4">Peer control Commands (click to expand/collapse)</td></tr>
</thead>
<tbody>

    </tr>
        <td colspan="2">
            <input type="text" maxlength="30" class="input_32_table" id="wgm_PeerImport">
            <legend>Import from <% nvram_get("productid"); %> Directory '/opt/etc/wireguard.d/'<legend>
        </td>
        <td rowspan="2">
            <input type="radio" name="wgm_IMPORT" id="wgm_ImportClient_enabled" class="input" value="enable" checked="">
            <label for="XIMPORT_PEER">Client</label>
			<br>
            <input type="radio" name="wgm_IMPORT" id="wgm_ImportServer_enabled" class="input" value="disable">
            <label for="XIMPORT_PEER">Server</label>
        </td>
        <td rowspan="2">
            <input type="button" class="button_gen" onclick="CMDExecutePeerImport();" value="Import" id="btnClientImport" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
        </td>
    </tr>

    <div style="line-height:10px;">&nbsp;</div>
    <tr>
       <td colspan="4" class="buttongen">
            <label>Upload from Local: ==> </label>
            <input type="file" name="inputfile" id="inputfile">
            <!--<legend>Upload from local PC<legend>-->
            <br>

            <pre id="wgm_WebUI_Import"></pre>

            <script type="text/javascript">
                document.getElementById('inputfile').addEventListener('change', function() {

                    var fr=new FileReader();
                    fr.onload=function(){
                        document.getElementById('wgm_WebUI_Import')
                                .textContent=fr.result;

                    }

                    fr.readAsText(this.files[0]);

                })

            </script>
        </td>

        <tr id="wg_export_setting">
            <th>Export configuration file</th>
            <td colspan="3">
            <input class="button_gen" type="button" value="<#1509#>" onClick="exportConfig();" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);"/>
            </td>
        </tr>

    </tr>
        <tr>
            <td class="settingname">DEFINED Peers</td>
            <td colspan="3">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('diag peers');" value="Show ALL" id="btnDiagPeers" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
            </td>
        </tr>
        <tr>
            <td class="settingname">ACTIVE Peers</td>
            <td colspan="3">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('list');" value="Show ALL" id="btnListPeers" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
            </td>
        </tr>
        <tr>
            <td>ALL Peers </td>
            <td colspan="3">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('stop');" value="Stop" id="btnStopPeers" style="color: indianred; background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('start');" value="Start" id="btnStartPeers" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('restart');" value="Restart" id="btnRestartPeers" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
        </tr>
        <tr>
            <td>Category: 'clients'</td>
            <td colspan="3">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('stop clients');" value="Stop" id="btnStopCategoryClients" style="color: indianred; background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('start clients');" value="Start" id="btnStartCategoryClients" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('restart clients');" value="Restart" id="btnRestartCategoryClients" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
        </tr>
        <tr>
            <td>Category: 'servers'</td>
            <td colspan="3">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('stop servers');" value="Stop" id="btnStopCategoryServers" style="color: indianred; background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('start servers');" value="Start" id="btnStartCategoryServers" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
                <input type="button" class="button_gen" onclick="CMDExecuteARG('restart servers');" value="Restart" id="btnRestartCategoryServers" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
        </tr>
</tbody>
</table>



<!--====================================================Client Configuration==========================================================-->
<div style="line-height:10px;">&nbsp;</div>
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#4D595D" class="FormTable">
<thead>
    <tr>
        <td colspan="2">Client Configuration</td>
    </tr>
</thead>
<tbody>
    <tr id="wgmc_unit_field" class="rept ew">
        <th>Select Client Index</th>
        <td>
            <select name="wgmc_unit" class="input_option" onChange="change_wgmc_unit(this.value);">
            <option class="content_input_fd" value="1" <% nvram_match("wgmc_unit", "1", "selected"); %>>1</option>
            <option class="content_input_fd" value="2" <% nvram_match("wgmc_unit", "2", "selected"); %>>2</option>
            <option class="content_input_fd" value="3" <% nvram_match("wgmc_unit", "3", "selected"); %>>3</option>
            <option class="content_input_fd" value="4" <% nvram_match("wgmc_unit", "4", "selected"); %>>4</option>
            <option class="content_input_fd" value="5" <% nvram_match("wgmc_unit", "5", "selected"); %>>5</option>
            <option class="content_input_fd" value="6" <% nvram_match("wgmc_unit", "6", "selected"); %>>6</option>
            <option class="content_input_fd" value="7" <% nvram_match("wgmc_unit", "7", "selected"); %>>7</option>
            <option class="content_input_fd" value="8" <% nvram_match("wgmc_unit", "8", "selected"); %>>8</option>
            <option class="content_input_fd" value="9" <% nvram_match("wgmc_unit", "9", "selected"); %>>9</option>
            </select>
        </td>
    </tr>
    <tr>
        <th>Description</th>
        <td>
            <input type="text" maxlength="40" name="wgc_desc" id="wgc_desc" onChange="confirmDescFieldUpdate(this.value);" class="input_32_table" value="<% nvram_get("wgmc_desc"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr id="wgc_auto_field" class="rept ew">
        <th>Auto start Type</th>
        <td>
            <select name="wgmc_auto_type" class="input_option" onChange="confirmAutoFieldUpdate(this.value);">
                <option value="Y" <% nvram_match("wgmc_auto", "Y", "selected"); %>>Auto Start</option>
                <option value="N" <% nvram_match("wgmc_auto", "N", "selected"); %>>DISABLED</option>
                <option value="P" <% nvram_match("wgmc_auto", "P", "selected"); %>>Policy Mode</option>
                <option value="S" <% nvram_match("wgmc_auto", "S", "selected"); %>>Site to Site</option>
                <option value="W" <% nvram_match("wgmc_auto", "W", "selected"); %>>WG-Quick</option>
             </select>
        </td>
    </tr>
    <tr id="wgmc_status">
		<th><div class="tooltip"><#3179#><span class="tooltiptext">For convenience, you can instantly change the connection state<br>by clicking the checkbox !</span></div></th>
        <td>
            <input type="checkbox" value="1" onclick="SwitchStatus();" name="wgmc_enable" class="input" <% nvram_match("wgmc_enable", "1", "checked"); %>><#188#></input>
        </td>
    </tr>
</tbody>
</table>


<table id="WgcStateTable" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
<tbody>
    <tr>
        <td>
            <input type="button" class="button_gen" onclick="CMDExecuteARG('stop wg1' + wgcindex);" value="Stop" id="btnStopWGClient" style="color: indianred; background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            <input type="button" class="button_gen" onclick="CMDExecuteARG('start wg1' + wgcindex);" value="Start" id="btnStartWGClient" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            <input type="button" class="button_gen" onclick="CMDExecuteARG('restart wg1' + wgcindex);" value="Restart" id="btnRestartWGClient" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            <input type="button" class="button_gen" onclick="confirmPeerDelete('wg1' + wgcindex);" value="Delete" id="btnDeleteWGClient" style="background: linear-gradient(rgb(234, 45, 8) 0%, rgb(234, 45, 8) 100%);">
			<input type="button" class="button_gen" onClick="ShowQRCode('wg11');" value="QR Code" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);"/>

            <div id="wgm_QRCode_block" style="display:none">
                <div style="display:flex; align-items: center;">
                    <div style="width:20px;height:20px;background-image:url('images/New_ui/disable.svg');cursor:pointer" onclick="HideQRCode();"></div>
                </div>
                <div id="qrcode"></div>
                <script type="text/javascript">
                    new QRCode(document.getElementById("qrcode"), "<% nvram_get("wgmc_desc"); %>" + "\n[Interface]" + "\nPrivateKey = " + "<% nvram_get("wgmc_priv"); %>" + "\nAddress = " + "<% nvram_get("wgmc_addr"); %>" + "\nDNS = " + "<% nvram_get("wgmc_dns"); %>" + "\n\n[Peer]" + "\nPublicKey = " + "<% nvram_get("wgmc_ppub"); %>" + "\nAllowedIPs = " + "<% nvram_get("wgmc_aips"); %>" + "\nEndPoint = " + "<% nvram_get("wgmc_ep_addr"); %>" + ":" + "<% nvram_get("wgmc_ep_port"); %>"  );
                </script>
            </div>
        </td>
    </tr>

</tbody>
</table>

<table id="WgcInterfaceTable" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
    <thead>
        <tr>
            <td colspan="2">Interface</td>
        </tr>
    </thead>
    <tr>
        <th>Private Key</th>
        <td>
            <input type="text" readonly maxlength="63" name="wgc_priv" id="wgc_priv" onChange="confirmPrivateKeyFieldUpdate(this.value);" class="input_32_table" value="<% nvram_get("wgmc_priv"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr>
        <th>Address</th>
        <td>
            <input type="text" maxlength="39" name="wgc_addr" id="wgc_addr" onChange="confirmAddressFieldUpdate(this.value);" class="input_32_table" value="<% nvram_get("wgmc_addr"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr>
        <th>DNS Server (Optional)</th>
        <td>
            <input type="text" maxlength="39" name="wgc_dns" id="wgc_dns" onChange="confirmDNSFieldUpdate(this.value);"class="input_32_table" value="<% nvram_get("wgmc_dns"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
	<tr>
		<th><div class="tooltip">MTU<span class="tooltiptext">WireGuard® will auto determine the<br>MTU if not specified<br><br>IPv4 = 1440<br>IPv6 = 1420<br>IPv4 PPoE = 1432<br>IPv6 PPoE = 1412<br><br>Some WireGuard® ISPs custom MTU<br>e.g. TorGuard = 1292<br><br>Another common value is 1380<br><br>Minimum accepted is 1280</span></div></th>
        <td>
            <input type="text" maxlength="39" name="wgc_mtu" id="wgc_mtu" onChange="confirmMTUFieldUpdate(this.value);"class="input_32_table" value="<% nvram_get("wgmc_mtu"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>

</table>
<table id="WgcPeerTable" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
    <thead>
        <tr>
            <td colspan="2">Peer</td>
        </tr>
    </thead>
    <tr>
        <th>Server Public Key</th>
            <td>
                <input type="text" readonly maxlength="63" name="wgc_ppub" id="wgc_ppub" onChange="confirmPublicKeyFieldUpdate(this.value);" class="input_32_table" value="<% nvram_get("wgmc_ppub"); %>" autocorrect="off" autocapitalize="off"></input>
            </td>
    </tr>
    <tr>
        <th>Preshared Key (Optional)</th>
        <td>
            <input type="text" readonly maxlength="63" name="wgc_psk" id="wgc_psk" onChange="confirmPreSharedKeyFieldUpdate(this.value);" class="input_32_table" value="<% nvram_get("wgmc_psk"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr>
		<th><div class="tooltip">Allowed IPs<span class="tooltiptext">You may specify shortcuts:<br><br>[ipv]4 or default<br>for<br>0.0.0.0/0<br><br>[ipv]6 or default6<br>for<br>::0/0</span></div></th>
        <td>
            <input type="text" maxlength="1023" name="wgc_aips" id="wgc_aips" onChange="confirmAllowedIPsFieldUpdate(this.value);" class="input_32_table" value="<% nvram_get("wgmc_aips"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr>
		<th><div class="tooltip">Endpoint Address:Port<span class="tooltiptext">Enter IP address or Domain name<br>of<br>'server' Peer and Port number</span></div></th>
        <td>
            <input type="text" maxlength="39" name="wgc_ep_addr" id="wgc_ep_addr" onChange="confirmEndpointAddressFieldUpdate(this.value);" class="input_32_table" value="<% nvram_get("wgmc_ep_addr"); %>" autocorrect="off" autocapitalize="off"></input> :
            <input type="text" maxlength="5" name="wgc_ep_port" id="wgc_ep_port" onChange="confirmEndpointPortFieldUpdate(this.value);" class="input_6_table" onKeyPress="return validator.isNumber(this,event);" value="<% nvram_get("wgmc_ep_port"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr>
        <th>Persistent Keepalive</th>
        <td>
            <input type="text" readonly maxlength="5" name="wgc_alive" id="wgc_alive" onChange="confirmPersistentKeepAliveFieldUpdate(this.value);" class="input_6_table" onKeyPress="return validator.isNumber(this,event);" value="<% nvram_get("wgmc_alive"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
</table>


<!--====================================================WireGuard Manager Configuration==========================================================-->
<div style="line-height:10px;">&nbsp;</div>
<table width="100%" border="1" align="center" cellpadding="2" cellspacing="0" bordercolor="#6b8fa3" class="FormTable SettingsTable" style="border:0px;" id="table_config">
<thead class="collapsible" id="scriptconfig">
    <tr><td colspan="2">Configuration Options (click to expand/collapse)</td></tr>
</thead>
<tbody style="">
    <tr>
        <td class="settingname">Current Configuration</td>
        <td>
            <input type="button" class="button_gen" onclick="CMDExecuteARG('?');" value="Show Infomation" id="btnShowConfig" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
        </td>
    </tr>
    </tr>
    <tr id="wgm_row_opt_use_entware_kernel_module">
        <td class="settingname">USE_ENTWARE_KERNEL_MODULE Allow use of 3rd Party WireGuard modules Enabled<br></td>
        <td class="settingvalue">
            <input type="checkbox" name="wgm_USE_ENTWARE_KERNEL_MODULE" id="wgm_USE_ENTWARE_KERNEL_MODULE_enabled" class="input" value="disable">
            <label for="XUSE_ENTWARE_KERNEL_MODULE">Yes</label>
        </td>
    </tr>
    <tr id="wgm_row_opt_noipv6">
        <td class="settingname">NOIPV6 - Disable IPv6 Enabled<br></td>
        <td class="settingvalue">
            <input type="checkbox" name="wgm_NOIPV6" id="wgm_NOIPV6_enabled" class="input" value="disable">
            <label for="XNOIPV6 - Disable IPv6">Yes</label>
        </td>
    </tr>
    <tr id="wgm_row_opt_disable_fc">
        <td class="settingname">DISABLE_FLOW_CACHE Enabled<br></td>
        <td class="settingvalue">
            <input type="checkbox" name="wgm_DISABLE_FLOW_CACHE_enabled" id="wgm_DISABLE_FLOW_CACHE_enabled" class="input" value="disable">
            <label for="XDISABLE_FLOW_CACHE">Yes</label>

        </td>
    </tr>
    <tr  id="wgm_row_opt_nocolor">
        <td class="settingname">NOCOLOR Disable ANSI colours Enabled<br></td>
        <td class="settingvalue">
            <input type="checkbox" name="wgm_NOCOLOR" id="wgm_NOCOLOR_enabled" class="input" value="disable">
            <label for="XNOCOLOR - Disable ANSI colour">Yes</label>
        </td>
    </tr>
    <tr id="wgm_row_opt_nomenu">
        <td class="settingname">NOMENU Disable MENU Enabled<br></td>
        <td class="settingvalue">
            <input type="checkbox" name="wgm_NOMENU" id="wgm_NOMENU_enabled" class="input" value="disable">
            <label for="XNOCOLOR - Disable MENU">Yes</label>
        </td>
    </tr>
    <tr id="wgm_row_opt_killswitch">
        <td class="settingname">KILLSWITCH Enabled)<br></td>
        <td class="settingvalue">
            <input type="checkbox" name="wgm_KILLSWITCH" id="wgm_KILLSWITCH_enabled" class="input" value="disable">
            <label for="XKILLSWITCH">Yes</label>
        </td>
    </tr>
    <tr id="wgm_row_opt_ignore_rogue220">
        <td class="settingname">ROGUE220IGNORE RPDB Priority 220 IGNORE Enabled<br></td>
        <td class="settingvalue">
            <input type="checkbox" name="wgm_KILLSWITCH" id="wgm_ROGUE220IGNORE_enabled" class="input" value="disable">
            <label for="XROGUE220IGNORE">Yes</label>
        </td>
    </tr>
    <tr id="wgm_row_opt_delete_rogue220">
        <td class="settingname">ROGUE220DELETE RPDB Priority 220 DELETE Enabled<br></td>
        <td class="settingvalue">
            <input type="checkbox" name="wgm_KILLSWITCH" id="wgm_ROGUE220DELETE_enabled" class="input" value="disable">
            <label for="XROGUE220DELETE">Yes</label>
        </td>
    </tr>
    <tr id="wgm_row_opt_webui">
        <td class="settingname">WebUI Enabled<br></td>
        <td class="settingvalue">
            <input type="checkbox"  name="wgm_WEBUI" id="wgm_WEBUI" class="input">
            <label for="XWEBUI">Yes</label>
        </td>
    </tr>
    <tr class="apply_gen" valign="top" height="35px">
        <td colspan="2" class="savebutton">
        <input type="button" onclick="SaveConfig();" value="Dummy SAVE Button" class="button_gen savebutton" name="button">
        </td>
    </tr>
</tbody>
</table>


<!--====================================================VPN Director Configuration==========================================================-->
<div style="line-height:10px;">&nbsp;</div>
<table width="100%" border="1" align="center" cellpadding="2" cellspacing="0" bordercolor="#6b8fa3" class="FormTable SettingsTable" style="border:0px;" id="table_config">
<thead class="collapsible" id="scriptconfig">
    <tr><td colspan="3">VPN Director Management Tools (click to expand/collapse)</td></tr>
</thead>

<tbody style="">
    <tr>
		<th><div class="tooltip">VPN Director rules<span class="tooltiptext">For convenience, use the VPN Director GUI to define the Selective Routing required, then clone them into WireGuard® Manager©, otherwise specify them manually.</span></div></th>
        <td>
            <input type="button" class="button_gen" onclick="CMDExecuteARG('vpndirector list');" value="Show" id="btnVPNDirectorList" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
        </td>
        <td>
            <input type="button" class="button_gen" onclick="confirmDeleteVPNDirector()" value="Delete" id="btnVPNDirectorDelete" style="background: linear-gradient(rgb(234, 45, 8) 0%, rgb(234, 45, 8) 100%);">
        </td>
    </tr>
    <tr>
        <td>
            <select name="VPNDirectorFilter" >
            <option value="wan">No Source Filter</option>
                <option value="wan">WAN</option>
                <option value="ovpnc1">OVPN Client 1</option>
                <option value="ovpnc2">OVPN Client 2</option>
                <option value="ovpnc3">OVPN Client 3</option>
                <option value="ovpnc4">OVPN Client 4</option>
                <option value="ovpnc5">OVPN Client 5</option>
             </select>
            <!--<legend>Legend Descriptions goes here</legend>-->
            <legend>Default Source: ALL</legend>
        </td>
        <td>
            <select name="VPNDirectorWGTarget" >
                <option value="">Default mapping</option>
                <option value="wg11">WG 'client' Peer 1</option>
                <option value="wg12">WG 'client' Peer 2</option>
                <option value="wg13">WG 'client' Peer 3</option>
                <option value="wg14">WG 'client' Peer 4</option>
                <option value="wg15">WG 'client' Peer 5</option>
             </select>
            <!--<legend>Legend Descriptions goes here</legend>-->
            <legend>Default Destination Mapping: tun11 to wg11 etc.</legend>
        </td>

        <td>
            <input type="button" class="button_gen" onclick="CMDExecuteARG('vpndirector clone');" value="Clone" id="btnVPNDirectorClone" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
        </td>
    </tr>

</tbody>
</table>


<!--====================================================Diagnostics==========================================================-->
<div style="line-height:10px;">&nbsp;</div>
<table width="100%" border="1" align="center" cellpadding="2" cellspacing="0" bordercolor="#6b8fa3" class="FormTable SettingsTable" style="border:0px;" id="table_config">
<thead class="collapsible" id="scriptconfig">
    <tr><td colspan="2">Diagnostic Tools (click to expand/collapse)</td></tr>
</thead>
<tbody style="">
    <tr>
        <td class="settingname">Diagnostics: Firewall rules</td>
        <td>
            <input type="button" class="button_gen" onclick="CMDExecuteARG('diag firewall');" value="Show Firewall" id="btnShowDiagsFirewall" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
        </td>
    </tr>
    <tr>
        <td class="settingname">Diagnostics: Selective Routing rules</td>
        <td>
            <input type="button" class="button_gen" onclick="CMDExecuteARG('diag rpdb');" value="Show RPDB" id="btnShowDiagsRPDB" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
        </td>
    </tr>
    <tr>
        <td class="settingname">Diagnostics: Routing</td>
        <td>
            <input type="button" class="button_gen" onclick="CMDExecuteARG('diag route');" value="Show Routes" id="btnShowDiagsRoute" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
        </td>
    </tr>
    </tr>
        <tr>
        <td class="settingname">Diagnostics: Miscellaneous</td>
        <td>
            <input type="button" class="button_gen" onclick="CMDExecuteARG('diag misc');" value="Show Misc" id="btnShowDiagsMisc" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
        </td>
    </tr>
</tbody>
</table>

<!--
<table width="100%" border="1" align="center" cellpadding="2" cellspacing="0" bordercolor="#6b8fa3" class="FormTable SettingsTable" style="border:0px;" id="table_config">
<thead class="collapsible" id="Base64Results">
    <tr><td colspan="2">Base64 -</td></tr>
</thead>
        <tr>
            <td colspan="2">Command Execute Output (Base64)</td>
            <input type="text" readonly maxlength="30" class="input_32_table" id="wgm_ExecuteTS">
            <textarea cols="190" rows="27" wrap="off" readonly="readonly" id="textarea" class="textarea_ssh_table" spellcheck="false" maxlength="4095" style="width:99%; font-family:'Courier New', Courier, mono; font-size:11px;"></textarea>
        </tr>
</table>-->

<div class="apply_gen" id="apply_btn">
    <input class="button_gen" onclick="applyRule();" type="button" value="<#1784#>"/>
</div>
<table id="WgcLogTable" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable" style="display:none">
    <tr>
        <td>
            <div style="margin-top:8px">
            <textarea class="textarea_ssh_table" style="width:99%; font-family:'Courier New', Courier, mono; font-size:13px;" cols="63" rows="25" readonly="readonly" wrap=off><% nvram_dump("wgc.log",""); %></textarea>
            </div>
            <div class="apply_gen">
                <input type="button" onClick="location.href=location.href" value="<#1636#>" class="button_gen">
            </div>
        </td>
    </tr>

    </table>
    </td>
</tr>
</tbody>
</table>
</td>
</tr>
</table>
</td>
<td width="10" align="center" valign="top">&nbsp;</td>
</tr>
</table>
</form>
<form method="post" name="chg_wgmc" action="apply.cgi" target="hidden_frame">
<input type="hidden" name="action_mode" value="chg_wgmc_unit">
<input type="hidden" name="action_script" value="">
<input type="hidden" name="action_wait" value="">
<input type="hidden" name="current_page" value="wg_manager.asp">
<input type="hidden" name="wgmc_unit" value="">
<input type="hidden" name="wgmc_auto_type" value="">
</form>

<div id="footer"></div>
</body>
</html>


