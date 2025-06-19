package com.google.android.gms.internal.play_billing;

import java.util.Iterator;

/* loaded from: classes2.dex */
public final class I implements Iterator {
    public final Iterator a;
    public boolean b;
    public Object c;

    public I(Iterator it2) {
        it2.getClass();
        this.a = it2;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.b || this.a.hasNext();
    }

    @Override // java.util.Iterator
    public final Object next() {
        if (!this.b) {
            return this.a.next();
        }
        Object obj = this.c;
        this.b = false;
        this.c = null;
        return obj;
    }

    @Override // java.util.Iterator
    public final void remove() {
        if (this.b) {
            throw new IllegalStateException("Can't remove after you've peeked at next");
        }
        this.a.remove();
    }
}
