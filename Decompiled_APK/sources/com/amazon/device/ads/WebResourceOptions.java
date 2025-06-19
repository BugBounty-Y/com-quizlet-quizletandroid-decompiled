package com.amazon.device.ads;

/* loaded from: classes.dex */
public class WebResourceOptions {
    private static String cdnHost = null;
    private static String[] jsNames = {"aps-mraid.js", "dtb-m.js", "omsdk-v1.js"};
    private static boolean useLocalOnly = false;

    public static String getCDNHost(String str) {
        String str2 = cdnHost;
        if (str2 == null) {
            str2 = DtbConstants.DTB_WEB_RESOURCES;
        }
        if ("omsdk-v1.js".equals(str)) {
            str2 = "video-player.aps.amazon-adsystem.com/static/omsdk/" + DtbConstants.INTEGRATED_OM_VERSION;
        }
        return !str2.endsWith("/") ? str2.concat("/") : str2;
    }

    public static String[] getCDNResources() {
        return jsNames;
    }

    public static boolean isLocalSourcesOnly() {
        return useLocalOnly;
    }

    public static void setCDNHost(String str) {
        if (str.equals(cdnHost)) {
            return;
        }
        cdnHost = str;
        DtbSharedPreferences.getInstance().resetWebResoucesLastPing();
        WebResourceService.getInstance().deleteWebDirContent();
    }

    public static void setCDNResources(String[] strArr) {
        jsNames = strArr;
    }

    public static void setLocalSourcesOnly(boolean z) {
        useLocalOnly = z;
    }
}
