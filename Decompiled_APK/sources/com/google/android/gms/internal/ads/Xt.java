package com.google.android.gms.internal.ads;

import java.util.AbstractMap;
import java.util.ConcurrentModificationException;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* loaded from: classes2.dex */
public abstract class Xt implements Iterator {
    public final /* synthetic */ int a = 0;
    public int b;
    public int c;
    public int d;
    public final /* synthetic */ AbstractMap e;

    public Xt(Zt zt) {
        this.e = zt;
        this.b = zt.e;
        this.c = zt.isEmpty() ? -1 : 0;
        this.d = -1;
    }

    public abstract Object a(int i);

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                if (this.c >= 0) {
                }
                break;
            default:
                if (this.c >= 0) {
                }
                break;
        }
        return false;
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                Zt zt = (Zt) this.e;
                if (zt.e != this.b) {
                    throw new ConcurrentModificationException();
                }
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                int i = this.c;
                this.d = i;
                Object objA = a(i);
                int i2 = this.c + 1;
                if (i2 >= zt.f) {
                    i2 = -1;
                }
                this.c = i2;
                return objA;
            default:
                com.google.android.gms.internal.mlkit_vision_barcode.r rVar = (com.google.android.gms.internal.mlkit_vision_barcode.r) this.e;
                if (rVar.e != this.b) {
                    throw new ConcurrentModificationException();
                }
                if (!hasNext()) {
                    throw new NoSuchElementException();
                }
                int i3 = this.c;
                this.d = i3;
                Object objA2 = a(i3);
                int i4 = this.c + 1;
                if (i4 >= rVar.f) {
                    i4 = -1;
                }
                this.c = i4;
                return objA2;
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                Zt zt = (Zt) this.e;
                if (zt.e != this.b) {
                    throw new ConcurrentModificationException();
                }
                AbstractC1981ds.L("no calls to next() since the last call to remove()", this.d >= 0);
                this.b += 32;
                zt.remove(zt.b()[this.d]);
                this.c--;
                this.d = -1;
                return;
            default:
                com.google.android.gms.internal.mlkit_vision_barcode.r rVar = (com.google.android.gms.internal.mlkit_vision_barcode.r) this.e;
                int i = rVar.e;
                int i2 = this.b;
                if (i != i2) {
                    throw new ConcurrentModificationException();
                }
                int i3 = this.d;
                if (!(i3 >= 0)) {
                    throw new IllegalStateException("no calls to next() since the last call to remove()");
                }
                this.b = i2 + 32;
                rVar.remove(rVar.b()[i3]);
                this.c--;
                this.d = -1;
                return;
        }
    }

    public Xt(com.google.android.gms.internal.mlkit_vision_barcode.r rVar) {
        this.e = rVar;
        this.b = rVar.e;
        this.c = rVar.isEmpty() ? -1 : 0;
        this.d = -1;
    }
}
