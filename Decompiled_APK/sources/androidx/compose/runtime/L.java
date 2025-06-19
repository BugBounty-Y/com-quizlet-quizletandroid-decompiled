package androidx.compose.runtime;

import java.util.Iterator;

/* loaded from: classes.dex */
public final class L implements Iterator, kotlin.jvm.internal.markers.a {
    public final /* synthetic */ int a = 0;
    public final A0 b;
    public final int c;
    public int d;
    public int e;

    public L(A0 a0, int i, int i2) {
        this.b = a0;
        this.c = i2;
        this.d = i;
        this.e = a0.h;
        if (a0.g) {
            C0.f();
        }
    }

    @Override // java.util.Iterator
    public final boolean hasNext() {
        switch (this.a) {
            case 0:
                return this.d < this.c;
            default:
                throw null;
        }
    }

    @Override // java.util.Iterator
    public final Object next() {
        switch (this.a) {
            case 0:
                A0 a0 = this.b;
                int i = a0.h;
                int i2 = this.e;
                if (i != i2) {
                    C0.f();
                }
                int i3 = this.d;
                this.d = C0.a(a0.a, i3) + i3;
                return new B0(a0, i3, i2);
            default:
                throw null;
        }
    }

    @Override // java.util.Iterator
    public final void remove() {
        switch (this.a) {
            case 0:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
            default:
                throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    public L(A0 a0, int i, M m, C0776c c0776c) {
        this.b = a0;
        this.c = i;
        this.d = a0.h;
    }
}
