package com.google.common.collect;

import java.util.Iterator;

/* loaded from: classes2.dex */
public abstract class F implements Iterator {
    public final Iterator a;

    public F(Iterator it2) {
        it2.getClass();
        this.a = it2;
    }

    public abstract Object a(Object obj);

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.a.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        return a(this.a.next());
    }

    @Override // java.util.Iterator
    public final void remove() {
        this.a.remove();
    }
}
