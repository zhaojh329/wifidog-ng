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

local uh = require "uhttpd"
local cjson = require "cjson"
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
        os.execute("ipset add wifidog-ng-mac " .. mac)
    else
        local cfg = config.get()
        os.execute("ipset add wifidog-ng-mac " .. mac .. " timeout " .. cfg.temppass_time)
    end
end

local function deny_user(mac)
    os.execute("ipset del wifidog-ng-mac " .. mac)
end

function M.new_term(ip, mac, token)
    terms[mac] = {ip = ip, token = token}
    if token then
        terms[mac].authed = true
        allow_user(mac)
    end
end

local function http_callback_auth(cl)
    local cfg = config.get()
    local token = uh.get_var(cl, "token")
    local ip = uh.get_remote_addr(cl)
    local mac = util.arp_get(cfg.gw_ifname, ip)

    if not mac then
        uh.log(uh.LOG_ERR, "Not found macaddr for " .. ip)
        uh.send_error(cl, 401, "Unauthorized", "Not found your macaddr")
        return uh.REQUEST_DONE
    end

    if token and #token > 0 then
        if uh.get_var(cl, "logout") then
            local url = string.format("%s&stage=logout&ip=%s&mac=%s&token=%s", cfg.auth_url, ip, mac, token)
            http.request(url)
            deny_user(mac)
        else
            local url = string.format("%s&stage=login&ip=%s&mac=%s&token=%s", cfg.auth_url, ip, mac, token)
            local r = http.request(url)

            if not r then
                uh.send_error(cl, 401, "Unauthorized")
                return uh.REQUEST_DONE
            end

            local auth = r:match("Auth: (%d)")
            if auth == "1" then
                allow_user(mac)
                uh.redirect(cl, 302, string.format("%s&mac=%s", cfg.portal_url, mac))
            else
                uh.redirect(cl, 302, string.format("%s&mac=%s", cfg.msg_url, mac))
                return uh.REQUEST_DONE
            end
        end
    else
        uh.send_error(cl, 401, "Unauthorized")
        return uh.REQUEST_DONE
    end
end

local function http_callback_temppass(cl)
    local cfg = config.get()
    local ip = uh.get_remote_addr(cl)
    local mac = util.arp_get(cfg.gw_ifname, ip)

    if not mac then
        uh.log(uh.LOG_ERR, "Not found macaddr for " .. ip)
        uh.send_error(cl, 401, "Unauthorized", "Not found your macaddr")
        return uh.REQUEST_DONE
    end

    local script = uh.get_var(cl, "script") or ""

    uh.send_header(cl, 200, "OK", -1)
    uh.header_end(cl)
    allow_user(mac, true)
    uh.chunk_send(cl, uh.get_var(cl, "script") or "");
    uh.request_done(cl)

    return uh.REQUEST_DONE
end

local function http_callback_404(cl, path)
    local cfg = config.get()

    if uh.get_http_method(cl) ~= uh.HTTP_METHOD_GET then
        uh.send_error(cl, 401, "Unauthorized")
        return uh.REQUEST_DONE
    end

    local ip = uh.get_remote_addr(cl)
    local mac = util.arp_get(cfg.gw_ifname, ip)
    if not mac then
        uh.log(uh.LOG_ERR, "Not found macaddr for " .. ip)
        uh.send_error(cl, 401, "Unauthorized", "Not found your macaddr")
        return uh.REQUEST_DONE
    end

    term = terms[mac]
    if not term then
        terms[mac] = {ip = ip}
    end

    term = terms[mac]

    if is_authed_user(term.mac) then
        uh.redirect(cl, 302, "%s&mac=%s", cfg.portal_url, mac)
        return uh.REQUEST_DONE
    end

    uh.send_header(cl, 200, "OK", -1)
    uh.header_end(cl)

    local header_host = uh.get_header(cl, "host")
    if apple_host[header_host] then
        local http_ver = uh.get_http_version(cl)
        if http_ver == uh.HTTP_VER_10 then
            if not term.apple then
                uh.chunk_send(cl, "fuck you")
                term.apple = true
                uh.request_done(cl)
                return uh.REQUEST_DONE
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

    uh.chunk_send(cl, string.format(redirect_html, cfg.login_url, ip, mac))
    uh.request_done(cl)

    return uh.REQUEST_DONE
end

local function on_request(cl, path)
    if path == "/auth" then
        return http_callback_auth(cl)
    elseif path == "/temppass" then
        return http_callback_temppass(cl)
    end

    return uh.REQUEST_CONTINUE
end

function M.init()
    local cfg = config.get()

    local srv = uh.new(cfg.gw_address, cfg.gw_port)

    srv:set_request_cb(on_request)
    srv:set_error404_cb(http_callback_404)

    if uh.SSL_SUPPORTED then
        local srv_ssl = uh.new(cfg.gw_address, cfg.gw_ssl_port)

        srv_ssl:ssl_init("/etc/wifidog-ng/ssl.crt", "/etc/wifidog-ng/ssl.key")

        srv_ssl:set_request_cb(on_request)
        srv_ssl:set_error404_cb(http_callback_404)
    end
end

return M
