-- Copyright 2016-2017 Dan Luedtke <mail@danrl.com>
-- Licensed to the public under the Apache License 2.0.

local map, section, net = ...
local ifname = net:get_interface():name()
local private_key, listen_port
local metric, mtu, preshared_key

local function generate_key_pair()
  local util = require("luci.util")
  
  local private = util.exec("wg genkey 2>/dev/null")
  
  local preshared = util.exec("wg genkey 2>/dev/null")
  
  local public = ""
  if private and #private > 0 then
    private = private:gsub("\n", "")
    preshared = preshared and preshared:gsub("\n", "") or ""
    public = util.exec("echo -n '" .. private .. "' | wg pubkey 2>/dev/null")
    public = public:gsub("\n", "")
  end
  
  return private, public, preshared
end

local function escape_json_string(s)
  if not s then return "" end
  s = s:gsub("\\", "\\\\")
  s = s:gsub('"', '\\"')
  s = s:gsub("\n", "\\n")
  s = s:gsub("\r", "\\r")
  s = s:gsub("\t", "\\t")
  return s
end

-- general ---------------------------------------------------------------------
private_key = section:taboption(
  "general",
  Value,
  "private_key",
  translate("Private Key"),
  translate("Required. Base64-encoded private key for this interface.")
)
private_key.password = true
private_key.datatype = "rangelength(44, 44)"
private_key.optional = false

local gen_btn = section:taboption("general", Button, "_generate")
gen_btn.title = " "
gen_btn.inputtitle = translate("Generate Keys")
gen_btn.inputstyle = "apply"
gen_btn.write = function()
  local private, public, preshared = generate_key_pair()
  if private and public then
    local private_escaped = escape_json_string(private)
    local public_escaped = escape_json_string(public)
    local preshared_escaped = escape_json_string(preshared)
    
    luci.http.prepare_content("text/html")
    luci.http.write([[
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <title>]] .. translate("WireGuard Keys Generated") .. [[</title>
    <style>
      body { 
        font-family: sans-serif; 
        padding: 30px; 
        background: #f9f9f9;
        color: #333333;
      }
      h3 { 
        color: #0066cc;
        margin-bottom: 20px;
      }
      .key-box {
        background: #ffffff;
        border: 1px solid #cccccc;
        border-radius: 4px;
        padding: 15px;
        margin: 10px 0 15px 0;
        font-family: monospace;
        font-size: 14px;
        word-break: break-all;
        color: #000000;
      }
      .key-label {
        font-weight: bold;
        margin-bottom: 5px;
        color: #444444;
      }
      .warning {
        background: #fff3cd;
        border: 1px solid #ffc107;
        color: #856404;
        padding: 10px;
        border-radius: 4px;
        margin: 15px 0;
      }
      .private-key {
        background: #fff0f0;
        border-color: #dc3545;
      }
      .preshared-key {
        background: #f0f7ff;
        border-color: #0066cc;
      }
      button {
        background: #0066cc;
        color: white;
        border: none;
        padding: 10px 20px;
        font-size: 14px;
        cursor: pointer;
        border-radius: 4px;
        margin: 5px;
      }
      button:hover {
        background: #0052a3;
      }
      button.copy {
        background: #28a745;
      }
      button.close {
        background: #6c757d;
      }
      .note {
        color: #666;
        font-size: 13px;
        margin-top: 5px;
      }
    </style>
    <script>
    var keyData = {
      private: "]] .. private_escaped .. [[",
      public: "]] .. public_escaped .. [[",
      preshared: "]] .. preshared_escaped .. [["
    };
    
    function copyToClipboard(type) {
      var text = type === 'private' ? keyData.private : 
                  (type === 'public' ? keyData.public : keyData.preshared);
      var textarea = document.createElement('textarea');
      textarea.value = text;
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
      
      var btn = event.target;
      var originalText = btn.innerHTML;
      btn.innerHTML = '✓ ]] .. translate("Copied!") .. [[';
      setTimeout(function() {
        btn.innerHTML = originalText;
      }, 1500);
    }
    
    function closeWindow() {
      window.close();
    }
    
    window.onload = function() {
      document.getElementById('private_key_display').textContent = keyData.private;
      document.getElementById('public_key_display').textContent = keyData.public;
      document.getElementById('preshared_key_display').textContent = keyData.preshared;
    };
    </script>
    </head>
    <body>
      <h3>🔑 ]] .. translate("WireGuard Keys Generated") .. [[</h3>
      
      <div class="warning">
        <strong>⚠️ ]] .. translate("Private Key MUST be kept secret!") .. [[</strong>
      </div>
      
      <div class="key-label">🔒 ]] .. translate("Private Key (SECRET - Keep safe!)") .. [[</div>
      <div class="key-box private-key" id="private_key_display"></div>
      <button class="copy" onclick="copyToClipboard('private')">📋 ]] .. translate("Copy Private Key") .. [[</button>
      
      <div class="key-label" style="margin-top:25px;">🔓 ]] .. translate("Public Key (Share with peers)") .. [[</div>
      <div class="key-box" id="public_key_display"></div>
      <button class="copy" onclick="copyToClipboard('public')">📋 ]] .. translate("Copy Public Key") .. [[</button>
      
      <div class="key-label" style="margin-top:25px;">🔐 ]] .. translate("Preshared Key (Optional - Extra security)") .. [[</div>
      <div class="key-box preshared-key" id="preshared_key_display"></div>
      <button class="copy" onclick="copyToClipboard('preshared')">📋 ]] .. translate("Copy Preshared Key") .. [[</button>
      <div class="note">]] .. translate("Preshared key adds post-quantum resistance. Will be saved in Advanced tab.") .. [[</div>
      
      <p style="margin-top: 30px;">
        <button class="close" onclick="closeWindow()">✖ ]] .. translate("Close Window") .. [[</button>
      </p>
    </body>
    </html>
    ]])
    return
  else
    luci.http.redirect(luci.http.getenv("REQUEST_URI"))
  end
end

local pub_display = section:taboption("general", DummyValue, "_public_display")
pub_display.title = translate("Public Key")
pub_display.value = function()
  local private = map:get(section.section, "private_key")
  if private and #private > 0 then
    local util = require("luci.util")
    local public = util.exec("echo -n '" .. private .. "' | wg pubkey 2>/dev/null")
    public = public:gsub("\n", "")
    if public and #public > 0 then
      return public
    end
  end
  return translate("Will be calculated from private key")
end

listen_port = section:taboption(
  "general",
  Value,
  "listen_port",
  translate("Listen Port"),
  translate("Optional. UDP port used for outgoing and incoming packets.")
)
listen_port.datatype = "port"
listen_port.placeholder = "51820"
listen_port.default = "51820"
listen_port.optional = true

addresses = section:taboption(
  "general",
  DynamicList,
  "addresses",
  translate("Local IP Addresses"),
  translate("IP addresses of this WireGuard interface. ") ..
  translate("Both IPv4 and IPv6 addresses are supported. ") ..
  translate("<strong>Important:</strong> Must include subnet mask (e.g., 10.0.0.2/24)")
)
addresses.datatype = "ipaddr"
addresses.optional = true


-- advanced --------------------------------------------------------------------

metric = section:taboption(
  "advanced",
  Value,
  "metric",
  translate("Metric"),
  translate("Optional")
)
metric.datatype = "uinteger"
metric.placeholder = "40"
metric.default = "40"
metric.optional = true

mtu = section:taboption(
  "advanced",
  Value,
  "mtu",
  translate("MTU"),
  translate("Optional. Maximum Transmission Unit of tunnel interface.")
)
mtu.datatype = "range(1280,1500)"
mtu.placeholder = "1420"
mtu.default = "1420"
mtu.optional = true

-- Preshared Key
preshared_key = section:taboption(
  "advanced",
  Value,
  "preshared_key",
  translate("Preshared Key"),
  translate("Optional. Adds in an additional layer of symmetric-key " ..
            "cryptography for post-quantum resistance.")
)
preshared_key.password = true
preshared_key.datatype = "rangelength(44, 44)"
preshared_key.optional = true


-- peers -----------------------------------------------------------------------

local peers_section = map:section(
  TypedSection,
  "wireguard_" .. ifname,
  translate("Peers"),
  translate("Configure remote peers. Each peer requires its own public key and allowed IPs.")
)

peers_section.template = "cbi/tsection"
peers_section.anonymous = true
peers_section.addremove = true

-- Public Key
local public_key = peers_section:option(
  Value,
  "public_key",
  translate("Public Key"),
  translate("<strong>Required.</strong> Public key of the remote peer. ") ..
  translate("This must be the key generated on the peer device, not your own key.")
)
public_key.datatype = "rangelength(44, 44)"
public_key.optional = false

-- Allowed IPs
local allowed_ips = peers_section:option(
  DynamicList,
  "allowed_ips",
  translate("Allowed IPs"),
  translate("<strong>Required.</strong> IP addresses that this peer is allowed to use. ") ..
  translate("<strong>Critical:</strong> Use /32 for single IP (e.g., 10.0.0.3/32), ") ..
  translate("not /24. Using /24 will cause routing issues!")
)
allowed_ips.datatype = "ipaddr"
allowed_ips.optional = false

-- Route Allowed IPs
local route_allowed_ips = peers_section:option(
  Flag,
  "route_allowed_ips",
  translate("Route Allowed IPs"),
  translate("Optional. Create routes for Allowed IPs for this peer.")
)

-- Endpoint Host
local endpoint_host = peers_section:option(
  Value,
  "endpoint_host",
  translate("Endpoint Host"),
  translate("<strong>Required for outgoing connection.</strong> IP address or hostname of the remote peer. ") ..
  translate("In LAN tests, use the peer's LAN IP (e.g., 192.168.1.x)."))
endpoint_host.placeholder = "192.168.1.3 or vpn.example.com"
endpoint_host.datatype = "host"
endpoint_host.optional = false
endpoint_host.rmempty = true

-- Endpoint Port
local endpoint_port = peers_section:option(
  Value,
  "endpoint_port",
  translate("Endpoint Port"),
  translate("Port of remote peer (default: 51820)."))
endpoint_port.placeholder = "51820"
endpoint_port.default = "51820"
endpoint_port.datatype = "port"
endpoint_port.optional = false
endpoint_port.rmempty = true

-- Persistent Keep Alive
local persistent_keepalive = peers_section:option(
  Value,
  "persistent_keepalive",
  translate("Persistent Keep Alive"),
  translate("Optional. Seconds between keep alive messages. ") ..
  translate("Set to 25 if peer is behind NAT. Set to 0 to disable."))
persistent_keepalive.datatype = "range(0, 65535)"
persistent_keepalive.placeholder = "0"
persistent_keepalive.default = "25"
persistent_keepalive.optional = false
persistent_keepalive.rmempty = true

local key_exchange_note = section:taboption("general", DummyValue, "_key_exchange_note")
key_exchange_note.title = " "
key_exchange_note.rawhtml = true
key_exchange_note.value = function()
  return [[
  <div style="margin:20px 0 10px 0; padding:15px; background:#e8f4fd; border-left:4px solid #0066cc; border-radius:4px;">
    <div style="display:flex; align-items:center;">
      <div style="font-size:24px; margin-right:15px;">🔑</div>
      <div>
        <strong style="color:#0066cc;">]] .. translate("Key Exchange Guide") .. [[</strong>
        <p style="margin:5px 0 0 0; color:#444;">
          ]] .. translate("1. Add Peers") .. [[<br>
          ]] .. translate("2. Generate keys using the 'Generate Keys' button above") .. [[<br>
          ]] .. translate("3. Copy your <strong>Public Key</strong> and share it with the peer") .. [[<br>
          ]] .. translate("4. In the Peers section below, enter the <strong>peer's Public Key</strong>") .. [[<br>
          ]] .. translate("5. For Allowed IPs, use <strong>/32</strong> format (e.g., 10.0.0.3/32)") .. [[
        </p>
      </div>
    </div>
  </div>
  ]]
end


function map.on_commit()
  luci.sys.call("(sleep 2; /etc/init.d/network restart) >/dev/null 2>&1 &")
end

local save_note = section:taboption("general", DummyValue, "_save_note")
save_note.title = " "
save_note.rawhtml = true
save_note.value = function()
  return [[
  <div style="margin:10px 0; padding:8px; background:#d4edda; border-left:4px solid #28a745; border-radius:4px;">
    <span style="color:#155724;">✅ ]] .. translate("Configuration will automatically restart after saving.") .. [[</span>
  </div>
  ]]
end
