package com.iab.omid.library.pubmatic.utils;

import android.os.Build;
import com.amazon.device.ads.DtbDeviceData;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class b {
    public static String a() {
        return Build.MANUFACTURER + "; " + Build.MODEL;
    }

    public static String b() {
        return "Android";
    }

    public static String c() {
        return Integer.toString(Build.VERSION.SDK_INT);
    }

    public static JSONObject d() throws JSONException {
        JSONObject jSONObject = new JSONObject();
        c.a(jSONObject, "deviceType", a());
        c.a(jSONObject, DtbDeviceData.DEVICE_DATA_OS_VERSION_KEY, c());
        c.a(jSONObject, "os", b());
        return jSONObject;
    }
}
