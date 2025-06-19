package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.text.TextUtils;

/* loaded from: classes2.dex */
public final class So implements Uo {
    public final boolean a;
    public final boolean b;
    public final String c;
    public final boolean d;
    public final int e;
    public final int f;
    public final int g;
    public final String h;

    public So(boolean z, boolean z2, String str, boolean z3, int i, int i2, int i3, String str2) {
        this.a = z;
        this.b = z2;
        this.c = str;
        this.d = z3;
        this.e = i;
        this.f = i2;
        this.g = i3;
        this.h = str2;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void b(Object obj) {
        Bundle bundle = ((Og) obj).b;
        bundle.putString("js", this.c);
        bundle.putInt("target_api", this.e);
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void c(Object obj) {
        Bundle bundle = ((Og) obj).a;
        bundle.putString("js", this.c);
        bundle.putBoolean("is_nonagon", true);
        C2601s7 c2601s7 = AbstractC2773w7.Q3;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        bundle.putString("extra_caps", (String) rVar.c.a(c2601s7));
        bundle.putInt("target_api", this.e);
        bundle.putInt("dv", this.f);
        bundle.putInt("lv", this.g);
        if (((Boolean) rVar.c.a(AbstractC2773w7.T5)).booleanValue()) {
            String str = this.h;
            if (!TextUtils.isEmpty(str)) {
                bundle.putString("ev", str);
            }
        }
        Bundle bundleD = AbstractC2096gb.d(bundle, "sdk_env");
        bundleD.putBoolean("mf", ((Boolean) W7.c.o()).booleanValue());
        bundleD.putBoolean("instant_app", this.a);
        bundleD.putBoolean("lite", this.b);
        bundleD.putBoolean("is_privileged_process", this.d);
        bundle.putBundle("sdk_env", bundleD);
        Bundle bundleD2 = AbstractC2096gb.d(bundleD, "build_meta");
        bundleD2.putString("cl", "756340629");
        bundleD2.putString("rapid_rc", "dev");
        bundleD2.putString("rapid_rollup", "HEAD");
        bundleD.putBundle("build_meta", bundleD2);
    }
}
