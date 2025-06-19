package com.google.android.gms.internal.mlkit_vision_document_scanner;

import java.util.ListIterator;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.a, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C3572a extends com.google.android.gms.internal.common.g implements ListIterator {
    public final int b;
    public int c;
    public final AbstractC3588c d;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C3572a(AbstractC3588c abstractC3588c, int i) {
        super(4);
        int size = abstractC3588c.size();
        if (i < 0 || i > size) {
            throw new IndexOutOfBoundsException(com.google.android.gms.internal.mlkit_vision_common.P3.d(i, size, "index"));
        }
        this.b = size;
        this.c = i;
        this.d = abstractC3588c;
    }

    public final Object a(int i) {
        return this.d.get(i);
    }

    @Override // java.util.ListIterator
    public final void add(Object obj) {
        throw new UnsupportedOperationException();
    }

    @Override // java.util.Iterator, java.util.ListIterator
    public final boolean hasNext() {
        return this.c < this.b;
    }

    @Override // java.util.ListIterator
    public final boolean hasPrevious() {
        return this.c > 0;
    }

    @Override // java.util.Iterator, java.util.ListIterator
    public final Object next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        int i = this.c;
        this.c = i + 1;
        return a(i);
    }

    @Override // java.util.ListIterator
    public final int nextIndex() {
        return this.c;
    }

    @Override // java.util.ListIterator
    public final Object previous() {
        if (!hasPrevious()) {
            throw new NoSuchElementException();
        }
        int i = this.c - 1;
        this.c = i;
        return a(i);
    }

    @Override // java.util.ListIterator
    public final int previousIndex() {
        return this.c - 1;
    }

    @Override // java.util.ListIterator
    public final void set(Object obj) {
        throw new UnsupportedOperationException();
    }
}
