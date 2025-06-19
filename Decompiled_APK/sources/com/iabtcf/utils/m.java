package com.iabtcf.utils;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class m implements Iterator {
    public final b a;

    public m(n nVar) {
        this.a = new b((c) nVar);
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.a.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        return this.a.next();
    }
}
