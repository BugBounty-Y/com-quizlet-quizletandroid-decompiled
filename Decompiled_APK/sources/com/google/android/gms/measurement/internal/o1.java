package com.google.android.gms.measurement.internal;

import android.net.Uri;
import android.text.TextUtils;

/* loaded from: classes2.dex */
public final class o1 extends l1 {
    public static final boolean V(String str) {
        String str2 = (String) AbstractC3893t.t.a(null);
        if (TextUtils.isEmpty(str2)) {
            return false;
        }
        for (String str3 : str2.split(",")) {
            if (str.equalsIgnoreCase(str3.trim())) {
                return true;
            }
        }
        return false;
    }

    public final String T(String str) {
        T t = this.c.a;
        r1.L(t);
        String strI0 = t.i0(str);
        if (TextUtils.isEmpty(strI0)) {
            return (String) AbstractC3893t.r.a(null);
        }
        Uri uri = Uri.parse((String) AbstractC3893t.r.a(null));
        Uri.Builder builderBuildUpon = uri.buildUpon();
        builderBuildUpon.authority(strI0 + "." + uri.getAuthority());
        return builderBuildUpon.build().toString();
    }

    public final boolean U(String str, String str2) {
        r1 r1Var = this.c;
        T t = r1Var.a;
        r1.L(t);
        com.google.android.gms.internal.measurement.E0 e0H0 = t.h0(str);
        if (e0H0 == null) {
            return false;
        }
        C3874j c3874j = r1Var.c;
        r1.L(c3874j);
        F fP0 = c3874j.P0(str);
        if (fP0 == null) {
            return false;
        }
        if (e0H0.G() && e0H0.u().n() == 100) {
            return true;
        }
        x1 x1Var = ((Y) this.b).l;
        Y.h(x1Var);
        if (x1Var.H0(str, fP0.i())) {
            return true;
        }
        return !TextUtils.isEmpty(str2) && Math.abs(str2.hashCode() % 100) < e0H0.u().n();
    }
}
