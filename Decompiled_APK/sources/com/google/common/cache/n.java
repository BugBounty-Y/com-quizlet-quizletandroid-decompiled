package com.google.common.cache;

import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicReferenceArray;

/* loaded from: classes2.dex */
public final class n implements Iterator {
    public int a;
    public int b = -1;
    public s c;
    public AtomicReferenceArray d;
    public J e;
    public H f;
    public H g;
    public final /* synthetic */ I h;
    public final /* synthetic */ int i;

    public n(I i, int i2) {
        this.i = i2;
        this.h = i;
        this.a = i.c.length - 1;
        a();
    }

    public final void a() {
        this.f = null;
        if (e() || f()) {
            return;
        }
        while (true) {
            int i = this.a;
            if (i < 0) {
                return;
            }
            s[] sVarArr = this.h.c;
            this.a = i - 1;
            s sVar = sVarArr[i];
            this.c = sVar;
            if (sVar.b != 0) {
                this.d = this.c.f;
                this.b = r0.length() - 1;
                if (f()) {
                    return;
                }
            }
        }
    }

    public final boolean b(J j) {
        Object obj;
        I i = this.h;
        try {
            long jA = i.o.a();
            Object key = j.getKey();
            Object obj2 = null;
            if (j.getKey() != null && (obj = j.h().get()) != null && !i.f(j, jA)) {
                obj2 = obj;
            }
            if (obj2 == null) {
                this.c.k();
                return false;
            }
            this.f = new H(i, key, obj2);
            this.c.k();
            return true;
        } catch (Throwable th) {
            this.c.k();
            throw th;
        }
    }

    public final Object c() {
        return d();
    }

    public final H d() {
        H h = this.f;
        if (h == null) {
            throw new NoSuchElementException();
        }
        this.g = h;
        a();
        return this.g;
    }

    public final boolean e() {
        J j = this.e;
        if (j == null) {
            return false;
        }
        while (true) {
            this.e = j.getNext();
            J j2 = this.e;
            if (j2 == null) {
                return false;
            }
            if (b(j2)) {
                return true;
            }
            j = this.e;
        }
    }

    public final boolean f() {
        while (true) {
            int i = this.b;
            if (i < 0) {
                return false;
            }
            AtomicReferenceArray atomicReferenceArray = this.d;
            this.b = i - 1;
            J j = (J) atomicReferenceArray.get(i);
            this.e = j;
            if (j != null && (b(j) || e())) {
                return true;
            }
        }
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        return this.f != null;
    }

    @Override // java.util.Iterator
    public Object next() {
        switch (this.i) {
            case 1:
                return d().a;
            case 2:
                return d().b;
            default:
                return c();
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        H h = this.g;
        if (h == null) {
            throw new IllegalStateException();
        }
        this.h.remove(h.a);
        this.g = null;
    }
}
