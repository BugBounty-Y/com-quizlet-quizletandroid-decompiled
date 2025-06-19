package com.google.android.gms.internal.ads;

import android.content.Context;
import android.os.Bundle;
import com.amazon.device.ads.DtbDeviceDataRetriever;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/* loaded from: classes2.dex */
public final class Dl {
    public static final Pattern p = Pattern.compile("\\?");
    public final C1765Re a;
    public final Context b;
    public final VersionInfoParcel c;
    public final C2023eq d;
    public final Xv e;
    public final ScheduledExecutorService f;
    public final String g;
    public final Tq h;
    public final Ek i;
    public final C2584rr j;
    public final Ih k;
    public final Object l = new Object();
    public String m;
    public List n;
    public Bundle o;

    public Dl(C1765Re c1765Re, Context context, VersionInfoParcel versionInfoParcel, C2023eq c2023eq, Xv xv, String str, Tq tq, Ek ek, L9 l9, ScheduledExecutorService scheduledExecutorService, C2584rr c2584rr, Ih ih) {
        this.a = c1765Re;
        this.b = context;
        this.c = versionInfoParcel;
        this.d = c2023eq;
        this.e = xv;
        this.g = str;
        this.h = tq;
        this.i = ek;
        this.f = scheduledExecutorService;
        this.j = c2584rr;
        this.k = ih;
    }

    public static final String d(String str) {
        try {
            return new JSONObject(str).optString("request_id", "");
        } catch (JSONException unused) {
            return "";
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:29:0x0160  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.AbstractC2460ov a(java.lang.String r19, java.lang.String r20) {
        /*
            Method dump skipped, instructions count: 427
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Dl.a(java.lang.String, java.lang.String):com.google.android.gms.internal.ads.ov");
    }

    public final String b(String str) throws JSONException {
        try {
            JSONObject jSONObject = new JSONObject(str);
            JSONArray jSONArray = jSONObject.getJSONArray("ad_types");
            if (jSONArray != null && DtbDeviceDataRetriever.ORIENTATION_UNKNOWN.equals(jSONArray.getString(0))) {
                jSONObject.put("ad_types", new JSONArray().put(this.g));
            }
            return jSONObject.toString();
        } catch (JSONException e) {
            com.google.android.gms.ads.internal.util.client.i.h("Failed to update the ad types for rendering. ".concat(e.toString()));
            return str;
        }
    }

    public final void c(int i) {
        Bundle bundle = this.i.d;
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.e7)).booleanValue()) {
            AbstractC1642h.t(com.google.android.gms.ads.internal.j.C.k, bundle, AbstractC1642h.b(i));
        }
    }
}
