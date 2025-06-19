package androidx.glance.layout;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public static final c c = new c(0, 0);
    public static final c d = new c(2, 0);
    public static final c e = new c(0, 1);
    public static final c f = new c(2, 1);
    public static final c g = new c(2, 2);
    public final int a;
    public final int b;

    public c(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!c.class.equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type androidx.glance.layout.Alignment");
        c cVar = (c) obj;
        return this.a == cVar.a && this.b == cVar.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "Alignment(horizontal=" + ((Object) a.b(this.a)) + ", vertical=" + ((Object) b.b(this.b)) + ')';
    }
}
