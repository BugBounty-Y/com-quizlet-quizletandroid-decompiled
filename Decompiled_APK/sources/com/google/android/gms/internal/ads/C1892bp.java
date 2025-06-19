package com.google.android.gms.internal.ads;

import android.os.Bundle;
import android.text.TextUtils;

/* renamed from: com.google.android.gms.internal.ads.bp, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1892bp implements Uo {
    public final String a;
    public final int b;
    public final int c;
    public final int d;
    public final boolean e;
    public final int f;

    public C1892bp(int i, int i2, int i3, int i4, boolean z, String str) {
        this.a = str;
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = z;
        this.f = i4;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void c(Object obj) {
        Bundle bundle = ((Og) obj).a;
        AbstractC2096gb.I(bundle, "carrier", this.a, !TextUtils.isEmpty(r0));
        int i = this.b;
        AbstractC2096gb.E(i, bundle, "cnt", i != -2);
        bundle.putInt("gnt", this.c);
        bundle.putInt("pt", this.d);
        Bundle bundleD = AbstractC2096gb.d(bundle, "device");
        bundle.putBundle("device", bundleD);
        Bundle bundleD2 = AbstractC2096gb.d(bundleD, "network");
        bundleD.putBundle("network", bundleD2);
        bundleD2.putInt("active_network_state", this.f);
        bundleD2.putBoolean("active_network_metered", this.e);
    }
}
