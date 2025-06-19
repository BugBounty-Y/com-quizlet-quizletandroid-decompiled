package com.google.android.gms.internal.ads;

import java.util.HashMap;

/* loaded from: classes2.dex */
public final /* synthetic */ class UD implements Pk, LE {
    public final /* synthetic */ C1832aG a;

    public /* synthetic */ UD(RD rd, C1832aG c1832aG, RC rc) {
        this.a = c1832aG;
    }

    @Override // com.google.android.gms.internal.ads.LE
    public int b(Object obj) {
        HE he = (HE) obj;
        HashMap map = ME.a;
        he.getClass();
        C1832aG c1832aG = this.a;
        String str = c1832aG.m;
        String str2 = he.b;
        return ((str2.equals(str) || str2.equals(ME.a(c1832aG))) && he.i(c1832aG, false) && he.j(c1832aG)) ? 1 : 0;
    }

    @Override // com.google.android.gms.internal.ads.Pk
    /* renamed from: b */
    public void mo10b(Object obj) {
        ((SD) obj).l(this.a);
    }
}
