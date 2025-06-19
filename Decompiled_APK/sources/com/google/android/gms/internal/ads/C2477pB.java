package com.google.android.gms.internal.ads;

import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.ads.pB, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2477pB implements Iterator {
    public final ArrayDeque a;
    public C2905zA b;

    public C2477pB(BA ba) {
        if (!(ba instanceof C2520qB)) {
            this.a = null;
            this.b = (C2905zA) ba;
            return;
        }
        C2520qB c2520qB = (C2520qB) ba;
        ArrayDeque arrayDeque = new ArrayDeque(c2520qB.g);
        this.a = arrayDeque;
        arrayDeque.push(c2520qB);
        BA ba2 = c2520qB.d;
        while (ba2 instanceof C2520qB) {
            C2520qB c2520qB2 = (C2520qB) ba2;
            this.a.push(c2520qB2);
            ba2 = c2520qB2.d;
        }
        this.b = (C2905zA) ba2;
    }

    @Override // java.util.Iterator
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public final C2905zA next() {
        C2905zA c2905zA;
        C2905zA c2905zA2 = this.b;
        if (c2905zA2 == null) {
            throw new NoSuchElementException();
        }
        do {
            ArrayDeque arrayDeque = this.a;
            c2905zA = null;
            if (arrayDeque == null || arrayDeque.isEmpty()) {
                break;
            }
            BA ba = ((C2520qB) arrayDeque.pop()).e;
            while (ba instanceof C2520qB) {
                C2520qB c2520qB = (C2520qB) ba;
                arrayDeque.push(c2520qB);
                ba = c2520qB.d;
            }
            c2905zA = (C2905zA) ba;
        } while (c2905zA.g() == 0);
        this.b = c2905zA;
        return c2905zA2;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.b != null;
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException();
    }
}
