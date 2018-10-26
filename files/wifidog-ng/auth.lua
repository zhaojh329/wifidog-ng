--[[
  Copyright (C) 2018 Jianhui Zhao <jianhuizhao329@gmail.com>
 
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.
 
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.
 
  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
  USA
 --]]

local copas = require "copas"
local httpd = require "wifidog-ng.httpd"
local http = require "socket.http"
local util = require "wifidog-ng.util"
local config = require "wifidog-ng.config"

local M = {}

local apple_host = {
    ["captive.apple.com"] = true,
    ["www.apple.com"] = true,
}

local terms = {}

local function is_authed_user(mac)
    local r = os.execute("ipset test wifidog-ng-mac " .. mac ..  " 2> /dev/null")
    return r == 0
end

local function allow_user(mac, temppass)
    if not temppass then
        terms[mac].authed = true
        os.execute("ipset add wifidog-ng-mac " .. mac)
    else
        local cfg = config.get()
        os.execute("ipset add wifidog-ng-mac " .. mac .. " timeout " .. cfg.temppass_time)
    end
end

local function deny_user(mac)
    os.execute("ipset del wifidog-ng-mac " .. mac)
end

function M.get_terms()
    local r = {}
    for k, v in pairs(terms) do
        if v.authed then
            r[k] = {ip = v.ip}
        end
    end

    return r
end

local function new_term(ip, mac, token)
    terms[mac] = {ip = ip, token = token}
    if token then
        terms[mac].authed = true
        allow_user(mac)
    end
end

local function http_callback_auth(req)
    local cfg = config.get()
    local params = req.params
    local token = params["token"]
    local ip = req.host
    local mac = util.arp_get(cfg.gw_ifname, ip)

    if not mac then
        req:error_403()
        return
    end

    if token and #token > 0 then
        if params["logout"] then
            local url = string.format("%s&stage=logout&ip=%s&mac=%s&token=%s", cfg.auth_url, ip, mac, token)
            http.request(url)
            deny_user(mac)
            req:redirect(string.format("%s&ip=%s&mac=%s", cfg.login_url, ip, mac))
        else
            local url = string.format("%s&stage=login&ip=%s&mac=%s&token=%s", cfg.auth_url, ip, mac, token)
            local r = http.request(url)

            if not r then
                req:error_403()
                return
            end

            local auth = r:match("Auth: (%d)")
            if auth == "1" then
                allow_user(mac)
                req:redirect(string.format("%s&mac=%s", cfg.portal_url, mac))
            else
                req:redirect(string.format("%s&mac=%s", cfg.msg_url, mac))
                return
            end
        end
    else
        req:error_403()
        return
    end
end

local function http_callback_temppass(req)
    local cfg = config.get()
    local ip = req.host
    local mac = util.arp_get(cfg.gw_ifname, ip)

    if not mac then
        req:error_403()
        return
    end

    local script = req.params["script"] or ""

    local content = "fuck you"
    local headers = {
        ["Content-Type"] = "text/plain",
        ["Content-Length"] = #script
    }
    req:send_head(200, headers)
    req:send(script)

    allow_user(mac, true)
end

local function http_callback_404(req)
    local cfg = config.get()

    if req.method ~= "GET" then
        req:error_403()
        return
    end

    local ip = req.host
    local mac = util.arp_get(cfg.gw_ifname, ip)
    if not mac then
        req:error_403()
        return
    end

    term = terms[mac]
    if not term then
        terms[mac] = {ip = ip}
    end

    term = terms[mac]

    if is_authed_user(mac) then
        req:redirect(string.format("%s&mac=%s", cfg.portal_url, mac))
        return
    end

    local header_host = req.headers["host"]
    if apple_host[header_host] then
        local http_ver = req.version
        if http_ver == "HTTP/1.0" then
            if not term.apple then
                local content = "fuck you"
                local headers = {
                    ["Content-Type"] = "text/plain",
                    ["Content-Length"] = #content
                }
                req:send_head(200, headers)
                req:send(content)
                term.apple = true
                return
            end
        end
    end

    local redirect_html = [[
        <!doctype html><html><head><title>Success</title>
        <script type="text/javascript">
        setTimeout(function() {location.replace('%s&ip=%s&mac=%s');}, 1);</script>
        <style type="text/css">body {color:#FFF}</style></head>
        <body>Success</body></html>
        ]]

    local content = string.format(redirect_html, cfg.login_url, ip, mac)
    local headers = {
        ["Content-Type"] = "text/html",
        ["Content-Length"] = #content
    }
    req:send_head(200, headers)
    req:send(content)
end

local function http_callback_ctl(req)
    local params = req.params
    local op = params["op"]

    if op == "roam" then
        local cfg = config.get()
        local ip, mac = params["ip"], params["mac"]

        if ip and mac then
            local url = string.format("%s&stage=roam&ip=%s&mac=%s", cfg.auth_url, ip, mac)
            local r = http.request(url) or ""
            local token = r:match("token=(%w+)")
            if token then
                new_term(ip, mac, token)
            end
        end
    elseif op == "kick" then
        local mac = params["mac"]
        if mac then
            deny_user(mac)
        end
    elseif op == "reload" then
        config.reload()
    end

    local content = "OK"
    local headers = {
        ["Content-Type"] = "text/plain",
        ["Content-Length"] = #content
    }
    req:send_head(200, headers)
    req:send(content)
end

function M.init()
    local cfg = config.get()

    local handlers = {
        ["404"] = http_callback_404,
        ["/wifidog/temppass"] = http_callback_temppass,
        ["/wifidog/auth"] = http_callback_auth,
        ["/wifidog/ctl"] = http_callback_ctl
    }

    httpd.new(cfg.gw_address, cfg.gw_port, handlers)
    print("Listen on:", cfg.gw_address, cfg.gw_port)

    httpd.new(cfg.gw_address, cfg.gw_ssl_port, handlers, {
        ssl = {
            mode = "server",
            protocol = "tlsv1_2",
            key = "/etc/wifidog-ng/ssl.key",
            certificate = "/etc/wifidog-ng/ssl.crt"
        }
    })
    print("Listen on:", cfg.gw_address, cfg.gw_ssl_port)
end

return M
