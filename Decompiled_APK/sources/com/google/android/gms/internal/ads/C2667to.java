package com.google.android.gms.internal.ads;

import android.os.Bundle;

/* renamed from: com.google.android.gms.internal.ads.to, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2667to implements Uo {
    public final double a;
    public final boolean b;

    public C2667to(double d, boolean z) {
        this.a = d;
        this.b = z;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void c(Object obj) {
        Bundle bundle = ((Og) obj).a;
        Bundle bundleD = AbstractC2096gb.d(bundle, "device");
        bundle.putBundle("device", bundleD);
        Bundle bundleD2 = AbstractC2096gb.d(bundleD, "battery");
        bundleD.putBundle("battery", bundleD2);
        bundleD2.putBoolean("is_charging", this.b);
        bundleD2.putDouble("battery_level", this.a);
    }
}
