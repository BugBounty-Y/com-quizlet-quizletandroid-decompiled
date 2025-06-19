package com.iabtcf.utils;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.PrimitiveIterator;

/* loaded from: classes2.dex */
public final class b implements Iterator, PrimitiveIterator.OfInt {
    public int a;
    public final /* synthetic */ c b;

    public b(c cVar) {
        this.b = cVar;
        this.a = cVar.a.isEmpty() ? -1 : cVar.a.nextSetBit(0);
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.a != -1;
    }

    @Override // java.util.PrimitiveIterator.OfInt
    public final int nextInt() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        int i = this.a;
        this.a = this.b.a.nextSetBit(i + 1);
        return i;
    }

    @Override // java.util.Iterator, java.util.PrimitiveIterator.OfInt
    public final Integer next() {
        return Integer.valueOf(nextInt());
    }
}
