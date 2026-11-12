// com.free.vpn.proxy.master.app  (AllConnect SDK)
// 目标：拿到 ApiConfig 明文与 AllConnect 节点响应
Java.perform(function () {
    function log(tag, s) { console.log("[" + tag + "] " + s); }

    try {
        var F = Java.use("c5.f");
        F.a.overload().implementation = function () {
            var r = this.a();
            log("c5.f.a()", r);
            return r;
        };
    } catch (e) { log("skip c5.f", e.message); }

    try {
        var B = Java.use("g5.b");
        B.a.overload().implementation = function () {
            var r = this.a();
            try { log("ApiConfig", JSON.stringify(r)); } catch (_) { log("ApiConfig", r); }
            return r;
        };
    } catch (e) { log("skip g5.b", e.message); }

    try {
        var T = Java.use("com.hotspot.vpn.tls.TlsPlusManager");
        T.f.overload("android.content.Context", "java.lang.String").implementation = function (c, s) {
            var r = this.f(c, s);
            log("TlsPlusManager.f IN", s);
            log("TlsPlusManager.f OUT", r);
            return r;
        };
    } catch (e) { log("skip TlsPlusManager", e.message); }

    // 所有 HTTP 往返
    try {
        var Builder = Java.use("okhttp3.Request$Builder");
        var RB = Java.use("okhttp3.Request");
        RB.toString.overload().implementation = function () {
            var s = this.toString();
            if (s.indexOf("http") >= 0) log("REQ", s);
            return s;
        };
    } catch (e) { log("skip okhttp", e.message); }

    // 节点响应体
    try {
        var Resp = Java.use("com.hotspot.vpn.allconnect.bean.NodeResponse");
        Resp.toString.overload().implementation = function () {
            var s = this.toString();
            log("NodeResponse", s);
            return s;
        };
    } catch (e) { log("skip NodeResponse", e.message); }
});
