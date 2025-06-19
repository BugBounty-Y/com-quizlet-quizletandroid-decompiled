package com.google.android.gms.internal.ads;

import org.json.JSONException;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.Bd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1668Bd {
    public final boolean a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;
    public final boolean i;
    public final boolean j;
    public final boolean k;
    public final boolean l;
    public final long m;
    public final long n;

    public C1668Bd(String str) throws JSONException {
        long jLongValue;
        long jLongValue2;
        JSONObject jSONObject = null;
        if (str != null) {
            try {
                jSONObject = new JSONObject(str);
            } catch (JSONException unused) {
            }
        }
        this.a = a(jSONObject, "aggressive_media_codec_release", AbstractC2773w7.P);
        this.b = b(jSONObject, "byte_buffer_precache_limit", AbstractC2773w7.j);
        this.c = b(jSONObject, "exo_cache_buffer_size", AbstractC2773w7.t);
        this.d = b(jSONObject, "exo_connect_timeout_millis", AbstractC2773w7.f);
        C2601s7 c2601s7 = AbstractC2773w7.e;
        if (jSONObject != null) {
            try {
                jSONObject.getString("exo_player_version");
            } catch (JSONException unused2) {
            }
        }
        this.e = b(jSONObject, "exo_read_timeout_millis", AbstractC2773w7.g);
        this.f = b(jSONObject, "load_check_interval_bytes", AbstractC2773w7.h);
        this.g = b(jSONObject, "player_precache_limit", AbstractC2773w7.i);
        this.h = b(jSONObject, "socket_receive_buffer_size", AbstractC2773w7.k);
        this.i = a(jSONObject, "use_cache_data_source", AbstractC2773w7.q4);
        b(jSONObject, "min_retry_count", AbstractC2773w7.l);
        this.j = a(jSONObject, "treat_load_exception_as_non_fatal", AbstractC2773w7.n);
        this.k = a(jSONObject, "enable_multiple_video_playback", AbstractC2773w7.U1);
        this.l = a(jSONObject, "use_range_http_data_source", AbstractC2773w7.W1);
        C2601s7 c2601s72 = AbstractC2773w7.X1;
        if (jSONObject != null) {
            try {
                jLongValue = jSONObject.getLong("range_http_data_source_high_water_mark");
            } catch (JSONException unused3) {
            }
        } else {
            jLongValue = ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(c2601s72)).longValue();
        }
        this.m = jLongValue;
        C2601s7 c2601s73 = AbstractC2773w7.Y1;
        if (jSONObject != null) {
            try {
                jLongValue2 = jSONObject.getLong("range_http_data_source_low_water_mark");
            } catch (JSONException unused4) {
            }
        } else {
            jLongValue2 = ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(c2601s73)).longValue();
        }
        this.n = jLongValue2;
    }

    public static final boolean a(JSONObject jSONObject, String str, C2601s7 c2601s7) {
        boolean zBooleanValue = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(c2601s7)).booleanValue();
        if (jSONObject != null) {
            try {
                return jSONObject.getBoolean(str);
            } catch (JSONException unused) {
            }
        }
        return zBooleanValue;
    }

    public static final int b(JSONObject jSONObject, String str, C2601s7 c2601s7) {
        if (jSONObject != null) {
            try {
                return jSONObject.getInt(str);
            } catch (JSONException unused) {
            }
        }
        return ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(c2601s7)).intValue();
    }
}
