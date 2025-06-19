package com.google.android.gms.internal.ads;

import android.content.SharedPreferences;
import java.util.ArrayList;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.s7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2601s7 {
    public final int a;
    public final String b;
    public final Object c;
    public final Object d;
    public final /* synthetic */ int e;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public /* synthetic */ C2601s7(int i, String str, Object obj, Object obj2, int i2) {
        this(i, obj, obj2, str);
        this.e = i2;
    }

    public static C2601s7 c(int i, int i2, String str) {
        return new C2601s7(1, str, Integer.valueOf(i), Integer.valueOf(i2), 1);
    }

    public static C2601s7 d(long j, long j2, String str) {
        return new C2601s7(1, str, Long.valueOf(j), Long.valueOf(j2), 2);
    }

    public static void e() {
        Object obj = null;
        ((ArrayList) com.google.android.gms.ads.internal.client.r.d.a.c).add(new C2601s7(1, "gads:sdk_core_constants:experiment_id", obj, obj, 4));
    }

    public final Object a(JSONObject jSONObject) {
        switch (this.e) {
            case 0:
                return Boolean.valueOf(jSONObject.optBoolean(this.b, ((Boolean) f()).booleanValue()));
            case 1:
                return Integer.valueOf(jSONObject.optInt(this.b, ((Integer) f()).intValue()));
            case 2:
                return Long.valueOf(jSONObject.optLong(this.b, ((Long) f()).longValue()));
            case 3:
                return Float.valueOf((float) jSONObject.optDouble(this.b, ((Float) f()).floatValue()));
            default:
                return jSONObject.optString(this.b, (String) f());
        }
    }

    public final Object b(SharedPreferences sharedPreferences) {
        switch (this.e) {
            case 0:
                return Boolean.valueOf(sharedPreferences.getBoolean(this.b, ((Boolean) f()).booleanValue()));
            case 1:
                return Integer.valueOf(sharedPreferences.getInt(this.b, ((Integer) f()).intValue()));
            case 2:
                return Long.valueOf(sharedPreferences.getLong(this.b, ((Long) f()).longValue()));
            case 3:
                return Float.valueOf(sharedPreferences.getFloat(this.b, ((Float) f()).floatValue()));
            default:
                return sharedPreferences.getString(this.b, (String) f());
        }
    }

    public final Object f() {
        return com.google.android.gms.ads.internal.client.r.d.c.i ? this.d : this.c;
    }

    public C2601s7(int i, Object obj, Object obj2, String str) {
        this.a = i;
        this.b = str;
        this.c = obj;
        this.d = obj2;
        ((ArrayList) com.google.android.gms.ads.internal.client.r.d.a.b).add(this);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public C2601s7(String str, String str2, String str3) {
        this(1, str2, str3, str);
        this.e = 4;
    }
}
