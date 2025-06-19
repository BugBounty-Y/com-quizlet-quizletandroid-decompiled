package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.RemoteException;

/* loaded from: classes2.dex */
public final /* synthetic */ class Si implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Ui b;

    public /* synthetic */ Si(Ui ui, int i) {
        this.a = i;
        this.b = ui;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                Ui ui = this.b;
                try {
                    Yi yi = ui.k;
                    int iG = yi.g();
                    C1929cj c1929cj = ui.o;
                    if (iG == 1) {
                        L8 l8 = c1929cj.a;
                        if (l8 != null) {
                            ui.k();
                            H8 h8 = (H8) ui.p.zzb();
                            Parcel parcelF3 = l8.f3();
                            AbstractC2857y5.e(parcelF3, h8);
                            l8.d4(1, parcelF3);
                            return;
                        }
                        return;
                    }
                    if (iG == 2) {
                        K8 k8 = c1929cj.b;
                        if (k8 != null) {
                            ui.k();
                            G8 g8 = (G8) ui.q.zzb();
                            Parcel parcelF32 = k8.f3();
                            AbstractC2857y5.e(parcelF32, g8);
                            k8.d4(1, parcelF32);
                            return;
                        }
                        return;
                    }
                    if (iG == 3) {
                        String strA = yi.a();
                        P8 p8 = strA == null ? null : (P8) c1929cj.f.get(strA);
                        if (p8 != null) {
                            if (yi.m() != null) {
                                ui.s("Google", true);
                            }
                            p8.l3((J8) ui.t.zzb());
                            return;
                        }
                        return;
                    }
                    if (iG == 6) {
                        U8 u8 = c1929cj.c;
                        if (u8 != null) {
                            ui.k();
                            u8.W0((Y8) ui.r.zzb());
                            return;
                        }
                        return;
                    }
                    if (iG != 7) {
                        com.google.android.gms.ads.internal.util.client.i.e("Wrong native template id!");
                        return;
                    }
                    P9 p9 = c1929cj.e;
                    if (p9 != null) {
                        M9 m9 = (M9) ui.s.zzb();
                        Parcel parcelF33 = p9.f3();
                        AbstractC2857y5.e(parcelF33, m9);
                        p9.d4(1, parcelF33);
                        return;
                    }
                    return;
                } catch (RemoteException e) {
                    com.google.android.gms.ads.internal.util.client.i.f("RemoteException when notifyAdLoad is called", e);
                    return;
                }
            default:
                Ui ui2 = this.b;
                ui2.l.n();
                Yi yi2 = ui2.k;
                synchronized (yi2) {
                    try {
                        InterfaceC2529qe interfaceC2529qe = yi2.i;
                        if (interfaceC2529qe != null) {
                            interfaceC2529qe.destroy();
                            yi2.i = null;
                        }
                        InterfaceC2529qe interfaceC2529qe2 = yi2.j;
                        if (interfaceC2529qe2 != null) {
                            interfaceC2529qe2.destroy();
                            yi2.j = null;
                        }
                        InterfaceC2529qe interfaceC2529qe3 = yi2.k;
                        if (interfaceC2529qe3 != null) {
                            interfaceC2529qe3.destroy();
                            yi2.k = null;
                        }
                        com.google.common.util.concurrent.e eVar = yi2.m;
                        if (eVar != null) {
                            eVar.cancel(false);
                            yi2.m = null;
                        }
                        C2313ld c2313ld = yi2.n;
                        if (c2313ld != null) {
                            c2313ld.cancel(false);
                            yi2.n = null;
                        }
                        yi2.l = null;
                        yi2.v.clear();
                        yi2.w.clear();
                        yi2.b = null;
                        yi2.c = null;
                        yi2.d = null;
                        yi2.e = null;
                        yi2.h = null;
                        yi2.o = null;
                        yi2.p = null;
                        yi2.q = null;
                        yi2.s = null;
                        yi2.t = null;
                        yi2.u = null;
                    } finally {
                    }
                }
                return;
        }
    }
}
