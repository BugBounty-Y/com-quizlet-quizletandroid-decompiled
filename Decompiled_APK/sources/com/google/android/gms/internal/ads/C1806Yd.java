package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.Yd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1806Yd extends AbstractC1794Wd {
    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final void l() {
    }

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final boolean r(String str) {
        String strA = com.google.android.gms.ads.internal.util.client.c.a(str, "MD5");
        InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.c.get();
        if (interfaceC2529qe != null && strA != null) {
            interfaceC2529qe.P(strA, this);
        }
        com.google.android.gms.ads.internal.util.client.i.h("VideoStreamNoopCache is doing nothing.");
        m(str, strA, "noop", "Noop cache is a noop.");
        return false;
    }
}
