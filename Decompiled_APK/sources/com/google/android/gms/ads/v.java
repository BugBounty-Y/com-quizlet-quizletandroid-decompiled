package com.google.android.gms.ads;

import android.os.RemoteException;
import com.google.android.gms.ads.internal.client.R0;
import com.google.android.gms.ads.internal.client.y0;
import com.google.android.gms.internal.ads.C1744Ob;

/* loaded from: classes2.dex */
public final /* synthetic */ class v implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;
    public final /* synthetic */ Object c;

    public /* synthetic */ v(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                k kVar = (k) this.b;
                try {
                    kVar.zza.b(((g) this.c).zza);
                    break;
                } catch (IllegalStateException e) {
                    C1744Ob.a(kVar.getContext()).d("BaseAdView.loadAd", e);
                    return;
                }
            default:
                f fVar = (f) this.b;
                try {
                    fVar.b.D0(R0.a(fVar.a, (y0) this.c));
                    break;
                } catch (RemoteException e2) {
                    com.google.android.gms.ads.internal.util.client.i.f("Failed to load ad.", e2);
                }
        }
    }
}
