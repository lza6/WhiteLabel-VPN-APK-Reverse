// com.free.vpn.super.hotspot.open (SuperUnlimited)
// 目标：账号态下的服务器列表响应
Java.perform(function () {
    function log(t, s) { console.log("[" + t + "] " + s); }
    try {
        var A = Java.use("R3.a");
        A.a.overload("java.lang.String").implementation = function (s) {
            var r = this.a(s);
            log("R3.a decrypt", String(r).slice(0, 2000));
            return r;
        };
    } catch (e) { log("skip R3.a", e.message); }
    try {
        var NM = Java.use("com.superunlimited.base.security.jni.NativeLegacy");
        NM.getKeyBytes.overload().implementation = function () {
            var r = this.getKeyBytes();
            log("getKeyBytes", JSON.stringify(Array.from(r)));
            return r;
        };
    } catch (e) { log("skip NativeLegacy", e.message); }
    try {
        var RB = Java.use("okhttp3.Request");
        RB.toString.overload().implementation = function () {
            var s = this.toString();
            if (s.indexOf("http") >= 0) log("REQ", s);
            return s;
        };
    } catch (e) { log("skip okhttp", e.message); }
});
