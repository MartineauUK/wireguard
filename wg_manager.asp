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
<script src="/state.js"></script>
<script src="/general.js"></script>
<script src="/help.js"></script>
<script src="/popup.js"></script>
<script src="/validator.js"></script>
<script src="/js/jquery.js"></script>
<script language="JavaScript" type="text/javascript" src="/ext/shared-jy/jquery.js"></script>
<script language="JavaScript" type="text/javascript" src="/client_function.js"></script>
<script language="JavaScript" type="text/javascript" src="/validator.js"></script>
<script>

<% get_wgc_parameter(); %>

var custom_settings = <% get_custom_settings(); %>;

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

}
function CMDExecute(){
/* As per RMerlin Wiki https://github.com/RMerl/asuswrt-merlin.ng/wiki/Addons-API */
   /* Retrieve value from input fields, and store in object */
   custom_settings.wgm_Execute = document.getElementById('wgm_Execute').value;

   /* Store object as a string in the amng_custom hidden input field */
   document.getElementById('amng_custom').value = JSON.stringify(custom_settings);

    if(validForm()){
        showLoading();
        document.form.submit();
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
<div class="formfonttitle">VPN - WireGuard® Client</div>
<div id="divSwitchMenu" style="margin-top:-40px;float:right;"></div
<div style="margin:10px 0 10px 5px;" class="splitLine"></div>

<table width="100%" border="1" align="center" cellpadding="4" cellspacing="0" bordercolor="#6b8fa3" class="FormTable">
<tr>
<th>WireGuard® Manager Version</th>
<td>
<input type="text" readonly maxlength="7" class="input_6_table" id="wgm_version">
</td>
</tr>
<tr>
<th>WireGuard® Kernel Module version</th>
<td>
<input type="text" readonly maxlength="30" class="input_12_table" id="wgm_Kernel">
</td>
</table>
<div class="formfonttitle">WireGuard® Manager© Command</div>

<table id="WgcBasicTable" width="100%" border="1" align="center" cellpadding="4" cellspacing="0" class="FormTable">
<thead>

<td colspan="2" class="execbutton">
<lable>wgm </lable>
<input type="text" maxlength="100" class="input_32_table" id="wgm_Execute">
<input type="button" class="button_gen" onclick="CMDExecute();" value="Execute" id="btnCMDExecute">
</td>
<tr>
<td colspan="2"><Client></td>
</tr>
</thead>
<tr id="wgc_unit_field" class="rept ew" value="<% nvram_get("wgmc_unit"); %>">
<th>Select Client Index</th>
<td>
<select name="wgc_unit" class="input_option" onChange="change_wgc_unit(this.value);">
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
  <legend></legend> </td>
</tr>
<tr id="wgmc_status">
<th><#3179#></th>
<td>
<input type="radio" value="1" name="wgmc_enable" class="input" <% nvram_match("wgmc_enable", "1", "checked"); %>><#188#></input>
<input type="radio" value="0" name="wgmc_enable" class="input" <% nvram_match("wgmc_enable", "0", "checked"); %>><#216#></input>
</td>
</tr>
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

