package com.google.android.gms.internal.ads;

import java.util.concurrent.RejectedExecutionException;

/* loaded from: classes2.dex */
public final class Jv extends Av {
    public Iv p;

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final void l() {
        Iv iv = this.p;
        if (iv != null) {
            iv.g();
        }
    }

    @Override // com.google.android.gms.internal.ads.Av
    public final void t(int i) {
        this.l = null;
        if (i == 1) {
            this.p = null;
        }
    }

    @Override // com.google.android.gms.internal.ads.Av
    public final void x(int i, Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Av
    public final void y() {
        Iv iv = this.p;
        if (iv != null) {
            try {
                iv.c.execute(iv);
            } catch (RejectedExecutionException e) {
                iv.d.h(e);
            }
        }
    }
}
