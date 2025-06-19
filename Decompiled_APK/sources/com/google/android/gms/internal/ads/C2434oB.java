package com.google.android.gms.internal.ads;

import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.ads.oB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2434oB extends Pu {
    public final C2477pB b;
    public Pu c;

    public C2434oB(C2520qB c2520qB) {
        super(1);
        this.b = new C2477pB(c2520qB);
        this.c = b();
    }

    @Override // com.google.android.gms.internal.ads.Pu
    public final byte a() {
        Pu pu = this.c;
        if (pu == null) {
            throw new NoSuchElementException();
        }
        byte bA = pu.a();
        if (!this.c.hasNext()) {
            this.c = b();
        }
        return bA;
    }

    public final C2819xA b() {
        C2477pB c2477pB = this.b;
        if (c2477pB.hasNext()) {
            return new C2819xA(c2477pB.next());
        }
        return null;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.c != null;
    }
}
