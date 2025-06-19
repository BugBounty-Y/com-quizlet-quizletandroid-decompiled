package androidx.compose.animation.core;

import androidx.camera.camera2.internal.AbstractC0147y;

/* loaded from: classes.dex */
public final class I implements InterfaceC0256n {
    public final A a;
    public final int b;
    public final long c;

    public I(A a, int i, long j) {
        this.a = a;
        this.b = i;
        this.c = j;
    }

    @Override // androidx.compose.animation.core.InterfaceC0256n
    public final N0 a(L0 l0) {
        return new S0(this.a.a(l0), this.b, this.c);
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof I)) {
            return false;
        }
        I i = (I) obj;
        if (i.a.equals(this.a) && i.b == this.b) {
            return i.c == this.c;
        }
        return false;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + ((AbstractC0147y.k(this.b) + (this.a.hashCode() * 31)) * 31);
    }
}
