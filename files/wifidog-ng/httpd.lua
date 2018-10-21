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

local _M = {}

local copas = require "copas"
local url = require "socket.url"

function _M.strsplit (str)
    local words = {}

    for w in string.gmatch(str, "%S+") do
        table.insert(words, w)
    end

    return words
end

local function parse_params(req)
    if not req.parsed_url.query then return nil end

    local params = {}
    req.params = params

    for parm in string.gmatch(req.parsed_url.query, "([^&]+)") do
        local k,v = string.match (parm, "(.*)=(.*)")
        k = url.unescape (k)
        v = url.unescape (v)
        if k ~= nil then
            if params[k] == nil then
                params[k] = v
            elseif type (params[k]) == "table" then
                table.insert (params[k], v)
            else
                params[k] = {params[k], v}
            end
        end
    end
end

local function parse_url(req)
    local def_url = string.format ("http://%s%s", req.headers.host or "", req.url or "")

    req.parsed_url = url.parse(def_url or '')
    req.parsed_url.port = req.parsed_url.port or req.port
    req.built_url = url.build(req.parsed_url)
    req.relpath = url.unescape(req.parsed_url.path)

    parse_params(req)
end

-- read and parses the request line
-- params:
--              req: request object
-- returns:
--              true if ok
--              false if connection closed
-- sets:
--              req.method: http method
--              req.url: url requested (as sent by the client)
--              req.version: http version (usually 'HTTP/1.1')
local function parse_request_line(req)
    local line, err = req.socket:receive()

    if not line then return nil end

    req.method, req.url, req.version = unpack(_M.strsplit(line))
    req.method = string.upper(req.method or 'GET')
    req.url = req.url or '/'

    return true
end

-- read and parses the request header fields
-- params:
--              req: request object
-- sets:
--              req.headers: table of header fields, as name => value
local function parse_headers(req)
    local headers = {}
    local prevval, prevname

    while true do
        local l, err = req.socket:receive()
        if not l or l == "" then
            req.headers = headers
            return
        end

        local _, _, name, value = string.find (l, "^([^: ]+)%s*:%s*(.+)")
        name = string.lower(name or '')
        if name then
            prevval = headers[name]
            if prevval then
                    value = prevval .. "," .. value
            end
            headers[name] = value
            prevname = name
        elseif prevname then
            headers[prevname] = headers[prevname] .. l
        end
    end
end

local status = {
    [200] = "OK",
    [404] = "Not Found",
    [302] = "Found",
    [403] = "Forbidden"
}

function _M.send_head(req, code, headers)
    local skt = req.socket
    skt:send(string.format("HTTP/1.1 %d %s\n", code, status[code]))
    skt:send("Server: wifidog-ng\n")

    for k, v in pairs(headers) do
        skt:send(string.format("%s: %s\n", k, v))
    end
    skt:send("\n")
end

function _M.handler_404(req)
    local content = [[<html>
<head><title>404 Not Found</title></head>
<body><center><h1>404 Not Found</h1></center></body>
</html>]]

    local skt = req.socket
    local headers = {
        ["Content-Type"] = "text/html",
        ["Content-Length"] = #content
    }

    _M.send_head(req, 404, headers)
    skt:send(content)
end

function _M.redirect(req, d)
    local skt = req.socket
    local content = "redirect"
    local headers = {
        ["Content-Type"] = "text/plain",
        ["Content-Length"] = #content,
        ["Location"] = d
    }

    _M.send_head(req, 302, headers)
    skt:send(content)
end

function _M.error_403(req)
    local content = [[<html>
<head><title>403 Forbidden</title></head>
<body><center><h1>Forbidden</h1></center></body>
</html>]]

    local skt = req.socket
    local headers = {
        ["Content-Type"] = "text/html",
        ["Content-Length"] = #content
    }

    _M.send_head(req, 403, headers)
    skt:send(content)
end

function _M.new(host, port, handlers, cfg)
    local server = assert(socket.bind(host, port))

    server:setoption("reuseaddr", true)

    handlers = handlers or {}
    cfg = cfg or {}

    local handler_404 = handlers["404"] or _M.handler_404

    copas.addserver(server, function(skt)
        local host, port = skt:getpeername()

        if cfg.ssl then
            skt = copas.wrap(skt):dohandshake(cfg.ssl)
        else
            skt = copas.wrap(skt)
        end

        local req = {
            host = host,
            port = port,
            socket = skt
        }

        while parse_request_line(req) do
            parse_headers(req)
            parse_url(req)

            local handler = handlers[req.relpath] or handler_404
            handler(req)
        end
    end)
end

return _M