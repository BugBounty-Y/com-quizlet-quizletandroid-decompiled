package com.google.android.gms.internal.measurement;

import java.util.Iterator;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.measurement.p, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3037p implements Iterator {
    public final /* synthetic */ int a;
    public int b = 0;
    public final /* synthetic */ C3042q c;

    public /* synthetic */ C3037p(C3042q c3042q, int i) {
        this.a = i;
        this.c = c3042q;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                if (this.b < this.c.a.length()) {
                }
                break;
            default:
                if (this.b < this.c.a.length()) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.Iterator
    public final /* bridge */ /* synthetic */ Object next() {
        switch (this.a) {
            case 0:
                int i = this.b;
                if (i >= this.c.a.length()) {
                    throw new NoSuchElementException();
                }
                this.b = i + 1;
                return new C3042q(String.valueOf(i));
            default:
                int i2 = this.b;
                C3042q c3042q = this.c;
                if (i2 >= c3042q.a.length()) {
                    throw new NoSuchElementException();
                }
                this.b = i2 + 1;
                return new C3042q(String.valueOf(c3042q.a.charAt(i2)));
        }
    }
}
