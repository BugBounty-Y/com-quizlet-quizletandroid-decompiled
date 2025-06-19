package com.google.android.gms.internal.ads;

import android.os.Looper;

/* loaded from: classes2.dex */
public final class JD {
    public final JE a;
    public final HD b;
    public int c;
    public Object d;
    public final Looper e;
    public boolean f;

    public JD(HD hd, JE je, Looper looper) {
        this.b = hd;
        this.a = je;
        this.e = looper;
    }

    public final void a() {
        AbstractC1795We.L(!this.f);
        this.f = true;
        C2436oD c2436oD = (C2436oD) this.b;
        if (!c2436oD.E && c2436oD.j.getThread().isAlive()) {
            c2436oD.h.a(14, this).a();
        } else {
            AbstractC2096gb.J("ExoPlayerImplInternal", "Ignoring messages sent after release.");
            b(false);
        }
    }

    public final synchronized void b(boolean z) {
        notifyAll();
    }
}
