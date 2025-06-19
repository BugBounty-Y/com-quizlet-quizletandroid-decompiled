package com.google.common.collect;

import java.util.NoSuchElementException;

/* loaded from: classes2.dex */
public final class t extends com.google.android.gms.internal.common.g {
    public final Object b;
    public boolean c;

    public t(Object obj) {
        super(5);
        this.b = obj;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return !this.c;
    }

    @Override // java.util.Iterator
    public final Object next() {
        if (this.c) {
            throw new NoSuchElementException();
        }
        this.c = true;
        return this.b;
    }
}
