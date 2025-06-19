package androidx.compose.material3;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class A3 {
    public final androidx.compose.foundation.shape.d a;
    public final androidx.compose.foundation.shape.d b;
    public final androidx.compose.foundation.shape.d c;
    public final androidx.compose.foundation.shape.d d;
    public final androidx.compose.foundation.shape.d e;

    public A3() {
        androidx.compose.foundation.shape.d dVar = AbstractC0770z3.a;
        androidx.compose.foundation.shape.d dVar2 = AbstractC0770z3.b;
        androidx.compose.foundation.shape.d dVar3 = AbstractC0770z3.c;
        androidx.compose.foundation.shape.d dVar4 = AbstractC0770z3.d;
        androidx.compose.foundation.shape.d dVar5 = AbstractC0770z3.e;
        this.a = dVar;
        this.b = dVar2;
        this.c = dVar3;
        this.d = dVar4;
        this.e = dVar5;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof A3)) {
            return false;
        }
        A3 a3 = (A3) obj;
        return Intrinsics.b(this.a, a3.a) && Intrinsics.b(this.b, a3.b) && Intrinsics.b(this.c, a3.c) && Intrinsics.b(this.d, a3.d) && Intrinsics.b(this.e, a3.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "Shapes(extraSmall=" + this.a + ", small=" + this.b + ", medium=" + this.c + ", large=" + this.d + ", extraLarge=" + this.e + ')';
    }
}
