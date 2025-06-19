package com.google.android.gms.internal.fido;

import java.util.ListIterator;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.fido.i, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2945i extends D implements ListIterator {
    public final int a;
    public int b;
    public final AbstractC2949m c;

    public C2945i(AbstractC2949m abstractC2949m, int i) {
        int size = abstractC2949m.size();
        if (i < 0 || i > size) {
            throw new IndexOutOfBoundsException(AbstractC2937a.o(i, size, "index"));
        }
        this.a = size;
        this.b = i;
        this.c = abstractC2949m;
    }

    public final Object a(int i) {
        return this.c.get(i);
    }

    @Override // java.util.ListIterator
    public final void add(Object obj) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Iterator, java.util.ListIterator
    public final boolean hasNext() {
        return this.b < this.a;
    }

    @Override // java.util.ListIterator
    public final boolean hasPrevious() {
        return this.b > 0;
    }

    @Override // java.util.Iterator, java.util.ListIterator
    public final Object next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        int i = this.b;
        this.b = i + 1;
        return a(i);
    }

    @Override // java.util.ListIterator
    public final int nextIndex() {
        return this.b;
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        if (!hasPrevious()) {
            throw new NoSuchElementException();
        }
        int i = this.b - 1;
        this.b = i;
        return a(i);
    }

    @Override // java.util.ListIterator
    public final int previousIndex() {
        return this.b - 1;
    }

    @Override // java.util.ListIterator
    public final void set(Object obj) {
        throw new UnsupportedOperationException();
    }
}
