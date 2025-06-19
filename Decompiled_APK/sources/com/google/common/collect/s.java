package com.google.common.collect;

import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes2.dex */
public final class s implements Iterator {
    public Iterator a;
    public Iterator b;
    public Iterator c;
    public ArrayDeque d;

    @Override // java.util.Iterator
    public final boolean hasNext() {
        Iterator it2;
        while (true) {
            Iterator it3 = this.b;
            it3.getClass();
            if (it3.hasNext()) {
                return true;
            }
            while (true) {
                Iterator it4 = this.c;
                if (it4 != null && it4.hasNext()) {
                    it2 = this.c;
                    break;
                }
                ArrayDeque arrayDeque = this.d;
                if (arrayDeque == null || arrayDeque.isEmpty()) {
                    break;
                }
                this.c = (Iterator) this.d.removeFirst();
            }
            it2 = null;
            this.c = it2;
            if (it2 == null) {
                return false;
            }
            Iterator it5 = (Iterator) it2.next();
            this.b = it5;
            if (it5 instanceof s) {
                s sVar = (s) it5;
                this.b = sVar.b;
                if (this.d == null) {
                    this.d = new ArrayDeque();
                }
                this.d.addFirst(this.c);
                if (sVar.d != null) {
                    while (!sVar.d.isEmpty()) {
                        this.d.addFirst((Iterator) sVar.d.removeLast());
                    }
                }
                this.c = sVar.c;
            }
        }
    }

    @Override // java.util.Iterator
    public final Object next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        Iterator it2 = this.b;
        this.a = it2;
        return it2.next();
    }

    @Override // java.util.Iterator
    public final void remove() {
        Iterator it2 = this.a;
        if (it2 == null) {
            throw new IllegalStateException("no calls to next() since the last call to remove()");
        }
        it2.remove();
        this.a = null;
    }
}
