package com.google.android.gms.internal.ads;

import android.content.Context;

/* renamed from: com.google.android.gms.internal.ads.vf, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2744vf implements InterfaceC2231jh {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ C2744vf(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final void E(Context context) {
        zzfcw zzfcwVar;
        switch (this.a) {
            case 0:
                try {
                    InterfaceC2911za interfaceC2911za = ((C2369mq) this.b).a;
                    try {
                        interfaceC2911za.N();
                        if (context != null) {
                            try {
                                interfaceC2911za.n0(new com.google.android.gms.dynamic.b(context));
                                return;
                            } finally {
                            }
                        }
                        return;
                    } finally {
                    }
                } catch (zzfcw e) {
                    com.google.android.gms.ads.internal.util.client.i.i("Cannot invoke onResume for the mediation adapter.", e);
                    return;
                }
            default:
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.b;
                if (interfaceC2529qe != null) {
                    interfaceC2529qe.onResume();
                    return;
                }
                return;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final void j(Context context) throws zzfcw {
        switch (this.a) {
            case 0:
                try {
                    try {
                        ((C2369mq) this.b).a.v();
                        break;
                    } catch (Throwable th) {
                        throw new zzfcw(th);
                    }
                } catch (zzfcw e) {
                    com.google.android.gms.ads.internal.util.client.i.i("Cannot invoke onDestroy for the mediation adapter.", e);
                    return;
                }
            default:
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.b;
                if (interfaceC2529qe != null) {
                    interfaceC2529qe.destroy();
                    break;
                }
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2231jh
    public final void o(Context context) throws zzfcw {
        switch (this.a) {
            case 0:
                try {
                    try {
                        ((C2369mq) this.b).a.U0();
                        break;
                    } catch (Throwable th) {
                        throw new zzfcw(th);
                    }
                } catch (zzfcw e) {
                    com.google.android.gms.ads.internal.util.client.i.i("Cannot invoke onPause for the mediation adapter.", e);
                    return;
                }
            default:
                InterfaceC2529qe interfaceC2529qe = (InterfaceC2529qe) this.b;
                if (interfaceC2529qe != null) {
                    interfaceC2529qe.onPause();
                    break;
                }
                break;
        }
    }
}
