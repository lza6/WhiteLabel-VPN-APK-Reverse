// com.vpnmasterx.fast
// 目标：拿 decryptData/decryptApi 的明文，以及 protobuf 请求响应
Java.perform(function () {
    function log(t, s) { console.log("[" + t + "] " + s); }
    try {
        var E = Java.use("com.vpnmasterx.networklib.EncryptUtil");
        E.decryptData.overload("java.lang.String").implementation = function (s) {
            var r = this.decryptData(s);
            log("decryptData IN", String(s).slice(0, 300));
            log("decryptData OUT", String(r).slice(0, 4000));
            return r;
        };
        E.decrypt.overload("int", "int", "java.lang.String", "java.lang.String", "long", "java.lang.String")
            .implementation = function (a, b, c, d, e, f) {
                var r = this.decrypt(a, b, c, d, e, f);
                log("decryptApi OUT", String(r).slice(0, 4000));
                return r;
            };
    } catch (e) { log("skip EncryptUtil", e.message); }

    try {
        var N = Java.use("com.vpnmasterx.lib.NativeApi");
        N.getAppId.overload().implementation = function () {
            var r = this.getAppId();
            log("getAppId", r);
            return r;
        };
        N.getUserAlias.overload("long", "java.lang.String").implementation = function (j, s) {
            var r = this.getUserAlias(j, s);
            log("getUserAlias(" + j + "," + s + ")", r);
            return r;
        };
    } catch (e) { log("skip NativeApi", e.message); }
});
