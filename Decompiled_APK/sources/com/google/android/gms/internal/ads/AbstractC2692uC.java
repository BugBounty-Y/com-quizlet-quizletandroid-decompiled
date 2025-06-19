package com.google.android.gms.internal.ads;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.NoSuchElementException;

/* renamed from: com.google.android.gms.internal.ads.uC, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2692uC implements Iterator, Closeable, AutoCloseable {
    public static final R3 g = new R3("eof ", 1);
    public M3 a;
    public C1722Kd b;
    public O3 c = null;
    public long d = 0;
    public long e = 0;
    public final ArrayList f = new ArrayList();

    static {
        AbstractC2457os.o(AbstractC2692uC.class);
    }

    public void close() {
    }

    @Override // java.util.Iterator
    /* renamed from: d, reason: merged with bridge method [inline-methods] */
    public final O3 next() {
        O3 o3A;
        O3 o3 = this.c;
        if (o3 != null && o3 != g) {
            this.c = null;
            return o3;
        }
        C1722Kd c1722Kd = this.b;
        if (c1722Kd == null || this.d >= this.e) {
            this.c = g;
            throw new NoSuchElementException();
        }
        try {
            synchronized (c1722Kd) {
                this.b.a.position((int) this.d);
                o3A = this.a.a(this.b, this);
                this.d = this.b.d();
            }
            return o3A;
        } catch (EOFException unused) {
            throw new NoSuchElementException();
        } catch (IOException unused2) {
            throw new NoSuchElementException();
        }
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        O3 o3 = this.c;
        R3 r3 = g;
        if (o3 == r3) {
            return false;
        }
        if (o3 != null) {
            return true;
        }
        try {
            this.c = next();
            return true;
        } catch (NoSuchElementException unused) {
            this.c = r3;
            return false;
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        throw new UnsupportedOperationException();
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getClass().getSimpleName());
        sb.append("[");
        int i = 0;
        while (true) {
            ArrayList arrayList = this.f;
            if (i >= arrayList.size()) {
                sb.append("]");
                return sb.toString();
            }
            if (i > 0) {
                sb.append(";");
            }
            sb.append(((O3) arrayList.get(i)).toString());
            i++;
        }
    }
}
