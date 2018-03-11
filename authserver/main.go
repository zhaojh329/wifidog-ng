/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
 */

package main

import (
    "flag"
    "log"
    "fmt"
    "time"
    "math/rand"
    "strconv"
    "net/http"
    "crypto/md5"
    "encoding/hex"
    "strings"
    "io/ioutil"
    "encoding/json"
    "github.com/joshbetz/config"
)

var loginPage = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WiFiDog-ng</title>
    <meta name="viewport" content="width=device-width,minimum-scale=1.0,maximum-scale=1.0,user-scalable=no" />
    <script>
        function load() {
            document.forms[0].action = "/wifidog/login" + window.location.search;
        }
    </script>
</head>
<body onload="load()">
    <div style="position: absolute; top: 50%; left:50%; margin: -150px 0 0 -150px; width: 300px; height: 300px;">
        <h1>Login</h1>
        <form method="POST">
            <button style="width: 300px; min-height: 20px;  padding: 9px 14px; font-size: 20px;" type="submit">Login</button>
        </form>
    </div>
</body>
</html>
`
var portalPage = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>WiFi Portal</title>
    <meta name="viewport" content="width=device-width,minimum-scale=1.0,maximum-scale=1.0,user-scalable=no" />
</head>
<body>
    <h1>Welcome to WiFi Portal</h1>
</body>
</html>
`
func generateToken(mac string) string {
    md5Ctx := md5.New()
    md5Ctx.Write([]byte(mac + strconv.FormatFloat(rand.Float64(), 'e', 6, 32)))
    cipherStr := md5Ctx.Sum(nil)
    return hex.EncodeToString(cipherStr)
}

type client struct {
    token string
    ip string
    url string
}

type weixinConfig struct {
    Appid string `json:"appid"`
    Shopid string `json:"shopid"`
    Secretkey string `json:"secretkey"`
}

func main() {
    port := flag.Int("port", 8912, "http service port")
    weixin := flag.Bool("wx", false, "weixin")

    flag.Parse()

    rand.Seed(time.Now().Unix())

    clients := make(map[string]client)

    c := config.New("weixin.json")
    weixincfg := &weixinConfig{}

    c.Get("appid", &weixincfg.Appid)
    c.Get("shopid", &weixincfg.Shopid)
    c.Get("secretkey", &weixincfg.Secretkey)

    http.HandleFunc("/wifidog/ping", func(w http.ResponseWriter, r *http.Request) {
        log.Println("ping", r.URL.RawQuery)
        fmt.Fprintf(w, "Pong")
    })

    http.HandleFunc("/wifidog/login", func(w http.ResponseWriter, r *http.Request) {
        if r.Method == "GET" {
            if *weixin {
                http.ServeFile(w, r, "www/weixin/login.html")
            } else {
                fmt.Fprintf(w, loginPage)
            }
        } else {
            gw_address := r.URL.Query().Get("gw_address")
            gw_port := r.URL.Query().Get("gw_port")
            ip := r.URL.Query().Get("ip")
            mac := r.URL.Query().Get("mac")
            url := r.URL.Query().Get("url")
            token := generateToken(mac)

            clients[mac] = client{token, ip, url}
        
            log.Println("New client:", mac, token)

            uri := fmt.Sprintf("http://%s:%s/wifidog/auth?token=%s", gw_address, gw_port, token)
            http.Redirect(w, r, uri, http.StatusFound)
        }
    })

    http.HandleFunc("/wifidog/auth", func(w http.ResponseWriter, r *http.Request) {
        stage := r.URL.Query().Get("stage")
        mac := strings.ToUpper(r.URL.Query().Get("mac"))
        token := r.URL.Query().Get("token")

        auth := 0

        if stage == "counters" {
            body, _ := ioutil.ReadAll(r.Body)
            r.Body.Close()
            log.Println("counters:", string(body))
            fmt.Fprintf(w, "{\"resp\":[]}")
            return;
        }

        if client, ok := clients[mac]; ok {
            if client.token == token {
                if stage == "login" {
                    auth = 1
                } else if stage == "logout" {
                    log.Println("logout:", mac)
                    delete(clients, mac)
                }
            } else {
                log.Printf("Invalid token(%s) for %s\n", token, mac)
            }
        } else {
            log.Println("Not found ", mac)
        }

        fmt.Fprintf(w, "Auth: %d", auth)
    })

    http.HandleFunc("/wifidog/weixin", func(w http.ResponseWriter, r *http.Request) {
        gw_address := r.URL.Query().Get("gw_address")
        gw_port := r.URL.Query().Get("gw_port")
        mac := r.URL.Query().Get("mac")
        ip := r.URL.Query().Get("ip")
        token := generateToken(mac)

        clients[mac] = client{token, ip, ""}

        log.Println("New Weixin client:", mac, token)

        uri := fmt.Sprintf("http://%s:%s/wifidog/auth?token=%s", gw_address, gw_port, token)
        http.Redirect(w, r, uri, http.StatusFound)
    })

    http.HandleFunc("/wifidog/portal", func(w http.ResponseWriter, r *http.Request) {
        fmt.Fprintf(w, portalPage)
    })

    http.HandleFunc("/wifidog/weixincfg", func(w http.ResponseWriter, r *http.Request) {
        js, _ := json.Marshal(weixincfg)
        fmt.Fprintf(w, string(js))
    })

    http.Handle("/", http.FileServer(http.Dir("./www")))

    log.Println("Listen on: ", *port)
    log.Println("weixin: ", *weixin)

    log.Fatal(http.ListenAndServe(":" + strconv.Itoa(*port), nil))
}
