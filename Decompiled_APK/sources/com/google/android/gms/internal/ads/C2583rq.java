package com.google.android.gms.internal.ads;

import java.util.LinkedList;

/* renamed from: com.google.android.gms.internal.ads.rq, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2583rq {
    public final int b;
    public final int c;
    public final LinkedList a = new LinkedList();
    public final Eq d = new Eq();

    public C2583rq(int i, int i2) {
        this.b = i;
        this.c = i2;
    }

    public final void a() {
        while (true) {
            LinkedList linkedList = this.a;
            if (linkedList.isEmpty()) {
                return;
            }
            C2755vq c2755vq = (C2755vq) linkedList.getFirst();
            com.google.android.gms.ads.internal.j.C.k.getClass();
            if (System.currentTimeMillis() - c2755vq.d < this.c) {
                return;
            }
            Eq eq = this.d;
            eq.f++;
            eq.b.b++;
            linkedList.remove();
        }
    }
}
