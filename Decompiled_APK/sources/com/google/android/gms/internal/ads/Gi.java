package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.InterfaceC1622x;

/* loaded from: classes2.dex */
public final class Gi implements CC {
    public final /* synthetic */ int a;
    public final Fi b;

    public /* synthetic */ Gi(Fi fi, int i) {
        this.a = i;
        this.b = fi;
    }

    @Override // com.google.android.gms.internal.ads.HC
    public final Object zzb() {
        switch (this.a) {
            case 0:
                return (InterfaceC1622x) this.b.c;
            case 1:
                return this.b;
            default:
                C1929cj c1929cj = (C1929cj) this.b.b;
                AbstractC1981ds.s(c1929cj);
                return c1929cj;
        }
    }
}
