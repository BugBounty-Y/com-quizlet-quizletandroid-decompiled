package com.perimeterx.mobile_sdk.block;

import java.util.Base64;
import java.util.regex.Pattern;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class b {
    public static final Pattern d;
    public final String a;
    public final String b;
    public final String c;

    static {
        Pattern patternCompile = Pattern.compile("^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$");
        Intrinsics.checkNotNullExpressionValue(patternCompile, "compile(...)");
        d = patternCompile;
    }

    public b(JSONObject json) throws JSONException {
        Intrinsics.checkNotNullParameter(json, "json");
        if (!json.isNull("action")) {
            com.google.mlkit.common.sdkinternal.b bVar = c.a;
            String string = json.getString("action");
            Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
            bVar.getClass();
            Intrinsics.checkNotNullParameter(string, "string");
            if (!Intrinsics.b(string, "captcha")) {
                Intrinsics.b(string, "block");
            }
        }
        if (!json.isNull("uuid")) {
            json.getString("uuid");
        }
        this.a = json.isNull("vid") ? null : json.getString("vid");
        this.b = json.isNull("appId") ? null : json.getString("appId");
        if (!json.isNull("collectorUrl")) {
            json.getString("collectorUrl");
        }
        this.c = json.getString("page");
    }

    public final String a() {
        String str = this.c;
        try {
            if (!d.matcher(str).matches()) {
                return null;
            }
            byte[] bArrDecode = Base64.getDecoder().decode(str);
            Intrinsics.checkNotNullExpressionValue(bArrDecode, "decode(...)");
            return new String(bArrDecode, Charsets.UTF_8);
        } catch (Exception unused) {
            return null;
        }
    }
}
