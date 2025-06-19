package androidx.compose.animation.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class K0 implements A {
    public final int a;
    public final int b;
    public final B c;

    public K0(int i, B b, int i2) {
        this((i2 & 1) != 0 ? 300 : i, (i2 & 2) != 0 ? 0 : 1000, (i2 & 4) != 0 ? C.a : b);
    }

    @Override // androidx.compose.animation.core.InterfaceC0256n
    public final N0 a(L0 l0) {
        return new U0(this.a, this.b, this.c);
    }

    public final boolean equals(Object obj) {
        if (obj instanceof K0) {
            K0 k0 = (K0) obj;
            if (k0.a == this.a && k0.b == this.b && Intrinsics.b(k0.c, this.c)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        return ((this.c.hashCode() + (this.a * 31)) * 31) + this.b;
    }

    @Override // androidx.compose.animation.core.A, androidx.compose.animation.core.InterfaceC0256n
    public final P0 a(L0 l0) {
        return new U0(this.a, this.b, this.c);
    }

    public K0(int i, int i2, B b) {
        this.a = i;
        this.b = i2;
        this.c = b;
    }
}
