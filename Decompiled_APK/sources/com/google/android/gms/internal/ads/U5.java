package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zze;

/* loaded from: classes2.dex */
public final class U5 extends AbstractBinderC1822a6 {
    public final C2578rl a;

    public U5(C2578rl c2578rl, String str) {
        this.a = c2578rl;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1866b6
    public final void F(int i) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1866b6
    public final void a0(zze zzeVar) {
        C2578rl c2578rl = this.a;
        if (c2578rl != null) {
            c2578rl.a(zzeVar.b());
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1866b6
    public final void a4(Y5 y5) {
        C2578rl c2578rl = this.a;
        if (c2578rl != null) {
            c2578rl.b(new V5(y5));
        }
    }
}
