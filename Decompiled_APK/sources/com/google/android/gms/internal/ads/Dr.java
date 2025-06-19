package com.google.android.gms.internal.ads;

import android.os.Parcel;
import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.zzfp;

/* loaded from: classes2.dex */
public final class Dr implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ C2670tr b;

    public /* synthetic */ Dr(C2670tr c2670tr, int i) {
        this.a = i;
        this.b = c2670tr;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                this.b.j();
                return;
            case 1:
                C2670tr c2670tr = this.b;
                synchronized (c2670tr) {
                    if (c2670tr.l.get()) {
                        try {
                            com.google.android.gms.ads.internal.client.N n = c2670tr.g;
                            zzfp zzfpVar = c2670tr.e;
                            Parcel parcelF3 = n.f3();
                            AbstractC2857y5.c(parcelF3, zzfpVar);
                            n.d4(1, parcelF3);
                        } catch (RemoteException unused) {
                            com.google.android.gms.ads.internal.util.client.i.h("Failed to call onAdsAvailable");
                            return;
                        }
                    }
                }
                return;
            case 2:
                C2670tr c2670tr2 = this.b;
                synchronized (c2670tr2) {
                    if (c2670tr2.l.get()) {
                        try {
                            com.google.android.gms.ads.internal.client.N n2 = c2670tr2.g;
                            zzfp zzfpVar2 = c2670tr2.e;
                            Parcel parcelF32 = n2.f3();
                            AbstractC2857y5.c(parcelF32, zzfpVar2);
                            n2.d4(2, parcelF32);
                        } catch (RemoteException unused2) {
                            com.google.android.gms.ads.internal.util.client.i.h("Failed to call onAdsExhausted");
                            return;
                        }
                    }
                }
                return;
            default:
                C2670tr c2670tr3 = this.b;
                Fi fi = c2670tr3.n;
                if (fi != null) {
                    fi.z(null, "paeo_ts", c2670tr3.o.currentTimeMillis(), -1, -1, null, c2670tr3.p);
                    return;
                }
                return;
        }
    }
}
