package androidx.compose.animation.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class y0 implements x0 {
    public final Object a;
    public final Object b;

    public y0(Object obj, Object obj2) {
        this.a = obj;
        this.b = obj2;
    }

    @Override // androidx.compose.animation.core.x0
    public final Object a() {
        return this.a;
    }

    @Override // androidx.compose.animation.core.x0
    public final Object c() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof x0)) {
            return false;
        }
        x0 x0Var = (x0) obj;
        if (Intrinsics.b(this.a, x0Var.a())) {
            return Intrinsics.b(this.b, x0Var.c());
        }
        return false;
    }

    public final int hashCode() {
        Object obj = this.a;
        int iHashCode = (obj != null ? obj.hashCode() : 0) * 31;
        Object obj2 = this.b;
        return iHashCode + (obj2 != null ? obj2.hashCode() : 0);
    }
}
