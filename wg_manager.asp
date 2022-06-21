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
<link rel="stylesheet" href="index_style.css">a
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
<script language="JavaScript" type="text/javascript" src="/js/jquery.js"></script>
<script language="JavaScript" type="text/javascript" src="/switcherplugin/jquery.iphone-switch.js"></script>
<script language="JavaScript" type="text/javascript" src="/js/httpApi.js"></script>
<script language="JavaScript" type="text/javascript" src="/ext/shared-jy/jquery.js"></script>
<script language="JavaScript" type="text/javascript" src="/ext/wireguard/ExecuteResults.js"></script>
<!--<script language="JavaScript" type="text/javascript" src="/ext/wireguard/ExecutedTS.js"></script>-->
<script>
<% get_wgc_parameter(); %>
var custom_settings = <% get_custom_settings(); %>;
/*openvpn_unit = '<% nvram_get("wgmc_unit"); %>';*/

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

    document.getElementById('wgm_Execute').value = "";

    if (custom_settings.wgm_Execute_Result == undefined)
            document.getElementById("wgm_ExecuteResultsBase64").innerHTML = "N/A"
    else
           document.getElementById("wgm_ExecuteResultsBase64").innerHTML = atob(custom_settings.wgm_Execute_Result);

    $("thead").click(function(){
        $(this).siblings().toggle("fast");
    })

    $(".default-collapsed").trigger("click");
}
function UpdateResults(){

    document.getElementById("wgm_ExecuteResultsBase64").innerHTML = atob(custom_settings.wgm_Execute_Result);

    /*ShowExecutedTS();*/
    ShowExecuteResults();
}
function CMDExecute(){
   /* As per RMerlin Wiki https://github.com/RMerl/asuswrt-merlin.ng/wiki/Addons-API */
   /* Retrieve value from input fields, and store in object */
   custom_settings.wgm_Execute = document.getElementById('wgm_Execute').value;

   /* Store object as a string in the amng_custom hidden input field */
   document.getElementById('amng_custom').value = JSON.stringify(custom_settings);

    if(validForm()){
        showLoading();

        /*alert("Confirmation prompts such as\n\t\t'Are you sure you want to DELETE a Peer?\nobviously cannot be manually answered, so an affirmative auto reply\n\t\t'Y'\nwill be used'.\n\nSimilarly if you create a new Road-Warrior 'device' Peer, the Parent 'server' Peer will be automatically restarted so it can listen for the new Road-Warrior 'device' Peer, which may interrupt other Road-Warrior 'device' connections");*/

        document.form.submit();

        /*sleepThenAct();*/

        UpdateResults();
    }
}
function CMDExecuteARG(command){

    custom_settings.wgm_Execute = command;

   /* Store object as a string in the amng_custom hidden input field */
   document.getElementById('amng_custom').value = JSON.stringify(custom_settings);

    if(validForm()){
        showLoading();
        document.form.submit();

        /*sleepThenAct();*/

        UpdateResults();
    }
}
function CMDExecutePeerImport(command){

    custom_settings.wgm_Execute = "import "+document.getElementById('wgm_PeerImport').value;;

   /* Store object as a string in the amng_custom hidden input field */
   document.getElementById('amng_custom').value = JSON.stringify(custom_settings);

    if(validForm()){
        showLoading();
        document.form.submit();

        /*sleepThenAct();*/

        UpdateResults();
    }
}
function applyRule(){

    if(validForm()){
        showLoading();
        document.form.submit();
    }
}
function validForm(){

    return true;
}
function change_wgc_unit(unit){
    document.chg_wgc.wgc_unit.value=unit.toString();
    document.chg_wgc.submit();
}
/*function change_vpn_unit(val){
    document.form.action_mode.value = "change_vpn_client_unit";
    document.form.action = "apply.cgi";
    document.form.target = "";
    document.form.submit();
}*/
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
<input type="hidden" name="action_wait" value="5">
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
                            <div style="color: indianred;" class="formfonttitle">VPN - WireGuard® Client ***** EXPERIMENTAL Beta v0.5 *****</div>
                            <div id="divSwitchMenu" style="margin-top:-40px;float:right;"></div
                            <div style="margin:10px 0 10px 5px;" class="splitLine"></div>

                            <table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
                                    <tr>
                                        <th>WireGuard® Manager Version</th>
                                            <td>
                                                <input type="text" readonly maxlength="7" class="input_6_table" id="wgm_version">

                                                <button type="button" class="button_gen navbutton" onclick="Help" id="btnHelp" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">Help</button>
                                            </td>
                                    </tr>
                                    <tr>
                                        <th>WireGuard® Kernel Module version</th>
                                            <td>
                                                <input type="text" readonly maxlength="30" class="input_12_table" id="wgm_Kernel">
                                            </td>
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
            <input type="button" class="button_gen" onclick="CMDExecute();" value="Execute" id="btnCMDExecute" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            <input type="button" onClick="location.href=location.href" value="Refresh Results" class="button_gen" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
        </td>
        <tr>
            <td colspan="2">Command Execute Output</td>
        </tr>
        <tr>
            <td style="padding: 0px;">
            <div style="color:#FFCC00;"><input type="checkbox" checked id="auto_refresh">Auto refresh</div>
            <!--<div class="web_frame"><textarea cols="190" rows="27" wrap="off" readonly="readonly" id="wgm_ExecuteResultsBase64" class="textarea_log_table" style="font-family:'Courier New', Courier, mono; font-size:12px;border: none;padding: 0px;">Empty</textarea></div>-->
            <div class="web_frame"><textarea cols="190" rows="27" wrap="off" readonly="readonly" id="wgm_ExecuteResultsBase64" class="textarea_log_table" style="font-family:'Courier New', Helvetica, MS UI Gothic, MS P Gothic, Microsoft Yahei UI, sans-serif; font-size:12px;border: none;padding: 0px;">Empty</textarea></div>
            <!--<textarea cols="190" rows="27" wrap="off" readonly="readonly" id="wgm_ExecuteResultsBase64" class="scrollabletextbox" spellcheck="false" maxlength="8192" style="width:99%; font-family:'Courier New', Courier, mono; font-size:11px;"></textarea>-->
            <!--<div class="web_frame" style="height:600px;overflow:auto;margin:5px><textarea cols="190" rows="27" wrap="off" readonly="readonly" id="wgm_ExecuteResultsBase64" class="textarea_ssh_table" spellcheck="false" maxlength="16384" style="width:99%; font-family:'Courier New', Courier, mono; font-size:11px;"></textarea></div>-->

        </tr>
</tbody>
</table>

<div style="line-height:10px;">&nbsp;</div>
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#4D595D" class="FormTable">
<thead class="collapsible">
    <tr><td colspan="2">Peer control Commands (click to expand/collapse)</td></tr>
</thead>
<tbody>

    </tr>
        <td colspan="2" class="execbutton">
            <input type="text" maxlength="30" class="input_32_table" id="wgm_PeerImport">
            <legend>Import from Directory /opt/etc/wireguard.d/<legend>
        </td>
        <td>
            <input type="radio" name="wgm_IMPORT" id="wgm_ImportClient_enabled" class="input" value="enable" checked="">
            <label for="XIMPORT_PEER">Client</label>
            <input type="radio" name="wgm_IMPORT" id="wgm_ImportServer_enabled" class="input" value="disable">
            <label for="XIMPORT_PEER">Server</label>
        </td>
        <td>
            <input type="button" class="button_gen" onclick="CMDExecutePeerImport();" value="Import" id="btnClientImport">
        </td>
    </tr>


        <tr>
            <td class="settingname">Peers defined</td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('diag peers');" value="Show ALL" id="btnDiagPeers" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
            </td>
        </tr>
        <tr>
            <td class="settingname">ACTIVE Peers</td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('list');" value="Show ALL" id="btnListPeers" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
            </td>
        </tr>
        <tr>
            <td class="settingname">ALL Peers </td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('stop');" value="Stop" id="btnStopPeers" style="color: indianred; background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('start');" value="Start" id="btnStartPeers" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('restart');" value="Restart" id="btnRestartPeers" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
        </tr>
        <tr>
            <td class="settingname">Category: 'clients'</td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('stop clients');" value="Stop" id="btnStopCategoryClients" style="color: indianred; background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('start clients');" value="Start" id="btnStartCategoryClients" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('restart clients');" value="Restart" id="btnRestartCategoryClients" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
        </tr>
        <tr>
            <td class="settingname">Category: 'servers'</td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('stop servers');" value="Stop" id="btnStopCategoryServers" style="color: indianred; background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('start servers');" value="Start" id="btnStartCategoryServers" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
            <td>
                <input type="button" class="button_gen" onclick="CMDExecuteARG('restart servers');" value="Restart" id="btnRestartCategoryServers" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            </td>
        </tr>
</tbody>
</table>


<div style="line-height:10px;">&nbsp;</div>
<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#4D595D" class="FormTable">
<thead>
    <tr>
        <td colspan="2">Client Configuration</td>
    </tr>
</thead>
<tbody>
    <tr id="vpn_unit_field" class="rept ew" value=openvpn_unit>

        <th>Select Client Index</th>
        <td>
            <select name="vpn_client_unit" class="input_option" onChange="change_vpn_unit(this.value);">
            <option class="content_input_fd" value="1" <% nvram_match("wgmc_unit", "1","selected"); %>>1</option>
            <option class="content_input_fd" value="2" <% nvram_match("wgmc_unit", "2","selected"); %>>2</option>
            <option class="content_input_fd" value="3" <% nvram_match("wgmc_unit", "3","selected"); %>>3</option>
            <option class="content_input_fd" value="4" <% nvram_match("wgmc_unit", "4","selected"); %>>4</option>
            <option class="content_input_fd" value="5" <% nvram_match("wgmc_unit", "5","selected"); %>>5</option>
            <option class="content_input_fd" value="6" <% nvram_match("wgmc_unit", "5","selected"); %>>6</option>
            <option class="content_input_fd" value="7" <% nvram_match("wgmc_unit", "5","selected"); %>>7</option>
            <option class="content_input_fd" value="8" <% nvram_match("wgmc_unit", "5","selected"); %>>8</option>
            <option class="content_input_fd" value="9" <% nvram_match("wgmc_unit", "5","selected"); %>>9</option>
            </select>
        </td>
    </tr>
    <tr>
        <th>Description</th>
        <td>
            <input type="text" readonly maxlength="40" name="wgc_desc" id="wgc_desc" class="input_32_table" value="<% nvram_get("wgmc_desc"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr id="wgc_auto" value="<% nvram_get("wgmc_auto"); %>">
        <th>Auto start Type</th>
        <td>
            <select name="AUTO_Start" >
                <option value="Y">Auto Start</option>
                <option value="N">DISABLED</option>
                <option value="P">Policy Mode</option>
                <option value="S">Site to Site</option>
                <option value="W">WG-Quick</option>
             </select>
            <!--<legend>Legend Descriptions goes here</legend>-->
        </td>
    </tr>
    <tr id="wgmc_status">
        <th><#3179#></th>
        <td>
            <input type="radio" value="1" name="wgmc_enable" class="input" <% nvram_match("wgmc_enable", "1", "checked"); %>><#188#></input>
            <input type="radio" value="0" name="wgmc_enable" class="input" <% nvram_match("wgmc_enable", "0", "checked"); %>><#216#></input>
        </td>
    </tr>
</tbody>
</table>


<table id="WgcStateTable" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
<tbody>
    <tr>
        <td colspan="2">
            <input type="button" class="button_gen" onclick="CMDExecuteARG('stop wg1'+wgcindex);" value="Stop" id="btnStopWGClient" style="color: indianred; background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            <input type="button" class="button_gen" onclick="CMDExecuteARG('start wg1'+wgcindex);" value="Start" id="btnStartWGClient" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            <input type="button" class="button_gen" onclick="CMDExecuteARG('restart wg1'+wgcindex);" value="Restart" id="btnRestartWGClient" style="background: linear-gradient(rgb(34, 164, 21) 0%, rgb(34, 164, 21) 100%);">
            <input type="button" class="button_gen" onclick="CMDExecuteARG('peer wg1'+wgcindex+' del');" value="Delete" id="btnDeleteWGClient" style="background: linear-gradient(rgb(234, 45, 8) 0%, rgb(234, 45, 8) 100%);">
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
            <input type="text" readonly maxlength="63" name="wgc_priv" id="wgc_priv" class="input_32_table" value="<% nvram_get("wgmc_priv"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr>
        <th>Address</th>
        <td>
            <input type="text" readonly maxlength="39" name="wgc_addr" id="wgc_addr" class="input_32_table" value="<% nvram_get("wgmc_addr"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr>
        <th>DNS Server (Optional)</th>
        <td>
            <input type="text" readonly maxlength="39" name="wgc_dns" id="wgc_dns" class="input_32_table" value="<% nvram_get("wgmc_dns"); %>" autocorrect="off" autocapitalize="off"></input>
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
                <input type="text" readonly maxlength="63" name="wgc_ppub" id="wgc_ppub" class="input_32_table" value="<% nvram_get("wgmc_ppub"); %>" autocorrect="off" autocapitalize="off"></input>
            </td>
    </tr>
    <tr>
        <th>Preshared Key (Optional)</th>
        <td>
            <input type="text" readonly maxlength="63" name="wgc_psk" id="wgc_psk" class="input_32_table" value="<% nvram_get("wgmc_psk"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr>
        <th>Allowed IPs</th>
        <td>
            <input type="text" readonly maxlength="1023" name="wgc_aips" id="wgc_aips" class="input_32_table" value="<% nvram_get("wgmc_aips"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr>
        <th>Endpoint Address:Port</th>
        <td>
            <input type="text" readonly maxlength="39" name="wgc_ep_addr" id="wgc_ep_addr" class="input_32_table" value="<% nvram_get("wgmc_ep_addr"); %>" autocorrect="off" autocapitalize="off"></input> :
            <input type="text" readonly maxlength="5" name="wgc_ep_port" id="wgc_ep_port" class="input_6_table" onKeyPress="return validator.isNumber(this,event);" value="<% nvram_get("wgmc_ep_port"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
    <tr>
        <th>Persistent Keepalive</th>
        <td>
            <input type="text" readonly maxlength="5" name="wgc_alive" id="wgc_alive" class="input_6_table" onKeyPress="return validator.isNumber(this,event);" value="<% nvram_get("wgmc_alive"); %>" autocorrect="off" autocapitalize="off"></input>
        </td>
    </tr>
</table>

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
    <tr class="even" id="wgm_row_opt_noipv6">
        <td class="settingname">NOIPV6 - Disable IPv6<br></td>
        <td class="settingvalue">
            <input type="radio" name="wgm_NOIPV6" id="wgm_NOIPV6_enabled" class="input" value="enable">
            <label for="XNOIPV6 - Disable IPv6">Yes</label>
            <input type="radio" name="wgm_NOIPV6"" id="wgm_NOIPV6_enabled" class="input" value="disable" checked="">
            <label for="XNOIPV6 - Allow IPv6">No</label>
        </td>
    </tr>
        <tr class="even" id="wgm_row_opt_nocolor">
        <td class="settingname">NOCOLOUR (Disable ANSI colours)<br></td>
        <td class="settingvalue">
            <input type="radio" name="wgm_NOCOLOR" id="wgm_NOCOLOR_enabled" class="input" value="enable">
            <label for="XNOCOLOR - Disable ANSI colour">Yes</label>
            <input type="radio" name="wgm_NOCOLOR"" id="wgm_NOCOLOR_enabled" class="input" value="disable" checked="">
            <label for="XNOCOLOR - Allow ANSI colour">No</label>
        </td>
    </tr>
    </tr>
        <tr class="even" id="wgm_row_opt_killswitch">
        <td class="settingname">KILLSWITCH (Activate)<br></td>
        <td class="settingvalue">
            <input type="radio" name="wgm_KILLSWITCH" id="wgm_KILLSWITCH_enabled" class="input" value="enable">
            <label for="XKILLSWITCH">Yes</label>
            <input type="radio" name="wgm_KILLSWITCH" id="wgm_KILLSWITCH_enabled" class="input" value="disable" checked="">
            <label for="XKILLSWITCH">No</label>
        </td>
    </tr>
    </tr>
        <tr class="even" id="wgm_row_opt_killswitch">
        <td class="settingname">USE_ENTWARE_KERNEL_MODULE (Activate)<br></td>
        <td class="settingvalue">
            <input type="radio" name="wgm_USE_ENTWARE_KERNEL_MODULE" id="wgm_USE_ENTWARE_KERNEL_MODULE_enabled" class="input" value="enable">
            <label for="XUSE_ENTWARE_KERNEL_MODULE">Yes</label>
            <input type="radio" name="wgm_USE_ENTWARE_KERNEL_MODULE" id="wgm_USE_ENTWARE_KERNEL_MODULE_enabled" class="input" value="disable" checked="">
            <label for="XUSE_ENTWARE_KERNEL_MODULE">No</label>
        </td>
    </tr>
    </tr>
        <tr class="even" id="wgm_row_opt_disable_fc">
        <td class="settingname">DISABLE_FLOW_CACHE (Activate)<br></td>
        <td class="settingvalue">
            <input type="radio" name="wgm_DISABLE_FLOW_CACHE" id="wgm_DISABLE_FLOW_CACHE_enabled" class="input" value="enable">
            <label for="XDISABLE_FLOW_CACHE">Yes</label>
            <input type="radio" name="wgm_DISABLE_FLOW_CACHE" id="wgm_DISABLE_FLOW_CACHE_enabled" class="input" value="disable" checked="">
            <label for="XDISABLE_FLOW_CACHE">No</label>
        </td>
    </tr>
    </tr>
        <tr class="even" id="wgm_row_opt_webui">
        <td class="settingname">WebUI Enabled<br></td>
        <td class="settingvalue">
            <input type="radio" name="wgm_WEBUI" id="wgm_WEBUI_enabled" class="input" value="enable" checked="">
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

<div style="line-height:10px;">&nbsp;</div>
<table width="100%" border="1" align="center" cellpadding="2" cellspacing="0" bordercolor="#6b8fa3" class="FormTable SettingsTable" style="border:0px;" id="table_config">
<thead class="collapsible" id="scriptconfig">
    <tr><td colspan="2">VPN Director Management Tools (click to expand/collapse)</td></tr>
</thead>

<tbody style="">
    <tr>
        <td class="settingname">VPN Director rules</td>
        <td>
            <input type="button" class="button_gen" onclick="CMDExecuteARG('vpndirector list');" value="Show" id="btnVPNDirectorList" style="background: linear-gradient(rgb(9, 99, 156) 0%, rgb(0, 48, 71) 100%);">
        </td>
        <td>
            <input type="button" class="button_gen" onclick="CMDExecuteARG('vpndirector delete');" value="Delete" id="btnVPNDirectorDelete" style="background: linear-gradient(rgb(234, 45, 8) 0%, rgb(234, 45, 8) 100%);">
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
<form method="post" name="chg_wgc" action="apply.cgi" target="hidden_frame">
<input type="hidden" name="action_mode" value="chg_wgc_unit">
<input type="hidden" name="action_script" value="">
<input type="hidden" name="action_wait" value="">
<input type="hidden" name="current_page" value="wg_manager.asp">
<input type="hidden" name="wgc_unit" value="">
</form>
<div id="footer"></div>
</body>
</html>



