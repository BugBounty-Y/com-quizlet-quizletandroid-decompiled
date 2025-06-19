package com.google.android.gms.internal.ads;

import android.os.Handler;
import com.skydoves.balloon.internals.DefinitionKt;

/* loaded from: classes2.dex */
public final class Xr implements Rr {
    public static Xr d;
    public float a;
    public Nr b;
    public Qr c;

    public static Xr b() {
        if (d == null) {
            Xr xr = new Xr();
            xr.a = DefinitionKt.NO_Float_VALUE;
            d = xr;
        }
        return d;
    }

    @Override // com.google.android.gms.internal.ads.Rr
    public final void a(boolean z) {
        if (z) {
            C2157hs.g.getClass();
            C2157hs.b();
            return;
        }
        C2157hs.g.getClass();
        Handler handler = C2157hs.i;
        if (handler != null) {
            handler.removeCallbacks(C2157hs.k);
            C2157hs.i = null;
        }
    }
}
