package com.google.android.gms.internal.ads;

import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.C1605l0;

/* loaded from: classes2.dex */
public final class Rp implements com.google.android.gms.ads.rewarded.a {
    public final /* synthetic */ int a;
    public final /* synthetic */ AbstractC2771w5 b;
    public final /* synthetic */ AbstractBinderC2814x5 c;

    public /* synthetic */ Rp(AbstractBinderC2814x5 abstractBinderC2814x5, AbstractC2771w5 abstractC2771w5, int i) {
        this.a = i;
        this.b = abstractC2771w5;
        this.c = abstractBinderC2814x5;
    }

    @Override // com.google.android.gms.ads.rewarded.a
    public final void j() {
        switch (this.a) {
            case 0:
                if (((Sp) this.c).j != null) {
                    try {
                        C1605l0 c1605l0 = (C1605l0) this.b;
                        c1605l0.d4(1, c1605l0.f3());
                        break;
                    } catch (RemoteException e) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
                        return;
                    }
                }
                break;
            default:
                if (((Tp) this.c).d != null) {
                    try {
                        com.google.android.gms.ads.internal.client.M m = (com.google.android.gms.ads.internal.client.M) this.b;
                        m.d4(1, m.f3());
                        break;
                    } catch (RemoteException e2) {
                        com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e2);
                    }
                }
                break;
        }
    }
}
