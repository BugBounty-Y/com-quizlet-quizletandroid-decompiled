package org.prebid.mobile.rendering.sdk.scripts;

/* loaded from: classes3.dex */
public class JsScriptData {
    public static final JsScriptData c = new JsScriptData("PBMJSLibraries/omsdk.js", "https://cdn.jsdelivr.net/gh/prebid/prebid-mobile-android@master/scripts/js/omsdk_v1.js");
    public static final JsScriptData d = new JsScriptData("PBMJSLibraries/mraid.js", "https://cdn.jsdelivr.net/gh/prebid/prebid-mobile-android@master/scripts/js/mraid.js");
    public final String a;
    public final String b;

    public JsScriptData(String str, String str2) {
        this.a = str;
        this.b = str2;
    }
}
