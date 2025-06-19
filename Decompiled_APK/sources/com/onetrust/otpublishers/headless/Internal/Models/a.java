package com.onetrust.otpublishers.headless.Internal.Models;

import android.content.Context;
import android.content.pm.PackageManager;
import androidx.annotation.NonNull;
import com.google.android.gms.measurement.internal.Z;
import com.onetrust.otpublishers.headless.Internal.Log.OTLogger;
import com.onetrust.otpublishers.headless.Internal.Preferences.d;
import java.util.Iterator;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class a {
    public final JSONObject a = new JSONObject();
    public final d b;
    public final Context c;

    public a(@NonNull Context context) {
        this.b = new d(context);
        this.c = context;
    }

    public final void a(String str, String str2, String str3, JSONObject jSONObject) throws JSONException {
        String str4;
        boolean zJ = com.onetrust.otpublishers.headless.Internal.a.j(str);
        JSONObject jSONObject2 = this.a;
        if (!zJ) {
            jSONObject2.put("InteractionType", str);
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str2)) {
            jSONObject2.put("Country", str2);
        }
        if (!com.onetrust.otpublishers.headless.Internal.a.j(str3)) {
            JSONObject jSONObject3 = new JSONObject(str3);
            if (jSONObject3.has("InteractionType") || jSONObject3.has("Country")) {
                jSONObject3.remove("InteractionType");
                jSONObject3.remove("Country");
            }
            Iterator<String> itKeys = jSONObject3.keys();
            while (itKeys.hasNext()) {
                String next = itKeys.next();
                try {
                    jSONObject2.put(next, jSONObject3.get(next));
                } catch (JSONException e) {
                    Z.p("Error on merging appendedCustomDSElements. Error msg = ", e, "DsDataElementPayload", 6);
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        Context context = this.c;
        sb.append(context.getApplicationInfo().loadLabel(context.getPackageManager()).toString());
        sb.append("/");
        try {
            str4 = context.getPackageManager().getPackageInfo(context.getPackageName(), 1).versionName;
        } catch (PackageManager.NameNotFoundException e2) {
            OTLogger.c("DsDataElementPayload", 6, "Error on getting Application versionName. Error msg = " + e2.getMessage());
            str4 = "";
        }
        sb.append(str4);
        String strL = android.support.v4.media.session.a.l(sb.toString(), " ", System.getProperty("http.agent"));
        if (!com.onetrust.otpublishers.headless.Internal.a.j(strL)) {
            jSONObject2.put("UserAgent", strL);
        }
        jSONObject.put("dsDataElements", jSONObject2);
        OTLogger.c("DsDataElementPayload", 4, "DS DataElement Object : " + jSONObject.getJSONObject("dsDataElements"));
    }
}
