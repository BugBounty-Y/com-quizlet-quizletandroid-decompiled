package com.google.android.gms.ads.internal.client;

import com.google.android.gms.internal.ads.Q9;

/* loaded from: classes2.dex */
public final class P0 extends AbstractBinderC1624z {
    public final com.google.android.gms.ads.w a;
    public final Q9 b;

    public P0(com.google.android.gms.ads.w wVar, Q9 q9) {
        this.a = wVar;
        this.b = q9;
    }

    @Override // com.google.android.gms.ads.internal.client.A
    public final void q() {
        Q9 q9;
        com.google.android.gms.ads.w wVar = this.a;
        if (wVar == null || (q9 = this.b) == null) {
            return;
        }
        wVar.b(q9);
    }

    @Override // com.google.android.gms.ads.internal.client.A
    public final void t2(zze zzeVar) {
        com.google.android.gms.ads.w wVar = this.a;
        if (wVar != null) {
            wVar.a(zzeVar.b());
        }
    }
}
