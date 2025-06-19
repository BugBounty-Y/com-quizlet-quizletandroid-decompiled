package com.google.android.gms.measurement.internal;

import android.os.Looper;
import android.os.SystemClock;
import com.google.android.gms.internal.ads.Ls;

/* loaded from: classes2.dex */
public final class g1 extends AbstractC3888q {
    public Ls d;
    public boolean e;
    public final androidx.appcompat.app.Q f;
    public final androidx.compose.foundation.lazy.layout.p0 g;
    public final androidx.work.impl.model.e h;

    public g1(Y y) {
        super(y);
        this.e = true;
        this.f = new androidx.appcompat.app.Q(this);
        androidx.compose.foundation.lazy.layout.p0 p0Var = new androidx.compose.foundation.lazy.layout.p0();
        p0Var.d = this;
        p0Var.c = new f1(p0Var, (Y) this.b, 0);
        ((Y) this.b).n.getClass();
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        p0Var.a = jElapsedRealtime;
        p0Var.b = jElapsedRealtime;
        this.g = p0Var;
        this.h = new androidx.work.impl.model.e(this);
    }

    @Override // com.google.android.gms.measurement.internal.AbstractC3888q
    public final boolean U() {
        return false;
    }

    public final void V() {
        S();
        if (this.d == null) {
            this.d = new Ls(Looper.getMainLooper(), 4);
        }
    }
}
