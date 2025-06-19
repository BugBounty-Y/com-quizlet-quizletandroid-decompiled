package com.google.android.gms.internal.ads;

import java.util.concurrent.LinkedBlockingDeque;

/* renamed from: com.google.android.gms.internal.ads.nq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2412nq {
    public final LinkedBlockingDeque a = new LinkedBlockingDeque();
    public final Zj b;
    public final C2227jd c;

    public C2412nq(Zj zj, C2227jd c2227jd) {
        this.b = zj;
        this.c = c2227jd;
    }

    public final synchronized com.google.common.util.concurrent.e a() {
        b(1);
        return (com.google.common.util.concurrent.e) this.a.poll();
    }

    public final synchronized void b(int i) {
        LinkedBlockingDeque linkedBlockingDeque = this.a;
        int size = i - linkedBlockingDeque.size();
        for (int i2 = 0; i2 < size; i2++) {
            linkedBlockingDeque.add(this.c.d(this.b));
        }
    }
}
