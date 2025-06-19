package com.google.gson.internal;

import com.squareup.moshi.A;
import com.squareup.moshi.z;
import java.util.AbstractMap;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.Map;
import java.util.NoSuchElementException;

/* loaded from: classes2.dex */
public abstract class k implements Iterator {
    public int b;
    public Map.Entry c;
    public final /* synthetic */ AbstractMap e;
    public final /* synthetic */ int a = 0;
    public Map.Entry d = null;

    public k(m mVar) {
        this.e = mVar;
        this.c = mVar.e.d;
        this.b = mVar.d;
    }

    public l a() {
        l lVar = (l) this.c;
        m mVar = (m) this.e;
        if (lVar == mVar.e) {
            throw new NoSuchElementException();
        }
        if (mVar.d != this.b) {
            throw new ConcurrentModificationException();
        }
        this.c = lVar.d;
        this.d = lVar;
        return lVar;
    }

    public z b() {
        z zVar = (z) this.c;
        A a = (A) this.e;
        if (zVar == a.c) {
            throw new NoSuchElementException();
        }
        if (a.e != this.b) {
            throw new ConcurrentModificationException();
        }
        this.c = zVar.d;
        this.d = zVar;
        return zVar;
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                if (((l) this.c) != ((m) this.e).e) {
                }
                break;
            default:
                if (((z) this.c) != ((A) this.e).c) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.Iterator
    public Object next() {
        switch (this.a) {
            case 0:
                return a();
            default:
                return b();
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                l lVar = (l) this.d;
                if (lVar == null) {
                    throw new IllegalStateException();
                }
                m mVar = (m) this.e;
                mVar.d(lVar, true);
                this.d = null;
                this.b = mVar.d;
                return;
            default:
                z zVar = (z) this.d;
                if (zVar == null) {
                    throw new IllegalStateException();
                }
                A a = (A) this.e;
                a.d(zVar, true);
                this.d = null;
                this.b = a.e;
                return;
        }
    }

    public k(A a) {
        this.e = a;
        this.c = a.c.d;
        this.b = a.e;
    }
}
