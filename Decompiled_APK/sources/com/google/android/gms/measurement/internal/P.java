package com.google.android.gms.measurement.internal;

import android.net.Uri;
import android.os.Bundle;
import android.text.TextUtils;

/* loaded from: classes2.dex */
public final class P {
    public final Y a;

    public P(Y y) {
        this.a = y;
    }

    public void a(Bundle bundle, String str) {
        String string;
        Y y = this.a;
        X x = y.j;
        Y.k(x);
        x.S();
        if (y.a()) {
            return;
        }
        if (bundle.isEmpty()) {
            string = null;
        } else {
            if (true == str.isEmpty()) {
                str = "auto";
            }
            Uri.Builder builder = new Uri.Builder();
            builder.path(str);
            for (String str2 : bundle.keySet()) {
                builder.appendQueryParameter(str2, bundle.getString(str2));
            }
            string = builder.build().toString();
        }
        if (TextUtils.isEmpty(string)) {
            return;
        }
        O o = y.h;
        Y.h(o);
        o.y.m(string);
        y.n.getClass();
        o.z.b(System.currentTimeMillis());
    }

    public boolean b() {
        Y y = this.a;
        try {
            com.google.android.gms.common.wrappers.b bVarA = com.google.android.gms.common.wrappers.c.a(y.a);
            if (bVarA != null) {
                return bVarA.c("com.android.vending", 128).versionCode >= 80837300;
            }
            I i = y.i;
            Y.k(i);
            i.o.f("Failed to get PackageManager for Install Referrer Play Store compatibility check");
            return false;
        } catch (Exception e) {
            I i2 = y.i;
            Y.k(i2);
            i2.o.g("Failed to retrieve Play Store version for Install Referrer", e);
            return false;
        }
    }

    public boolean c() {
        O o = this.a.h;
        Y.h(o);
        return o.z.a() > 0;
    }

    public boolean d() {
        if (!c()) {
            return false;
        }
        Y y = this.a;
        y.n.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        O o = y.h;
        Y.h(o);
        return jCurrentTimeMillis - o.z.a() > y.g.a0(null, AbstractC3893t.i0);
    }

    public P(r1 r1Var) {
        this.a = r1Var.l;
    }
}
