package com.squareup.moshi;

import java.util.Iterator;

/* loaded from: classes3.dex */
public final class t implements Iterator, Cloneable {
    public final o a;
    public final Object[] b;
    public int c;

    public t(o oVar, Object[] objArr, int i) {
        this.a = oVar;
        this.b = objArr;
        this.c = i;
    }

    public final Object clone() {
        return new t(this.a, this.b, this.c);
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.c < this.b.length;
    }

    @Override // java.util.Iterator
    public final Object next() {
        int i = this.c;
        this.c = i + 1;
        return this.b[i];
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException();
    }
}
