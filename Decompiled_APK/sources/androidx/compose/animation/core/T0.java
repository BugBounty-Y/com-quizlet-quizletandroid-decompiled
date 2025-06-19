package androidx.compose.animation.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class T0 {
    public final AbstractC0267t a;
    public final B b;

    public T0(AbstractC0267t abstractC0267t, B b) {
        this.a = abstractC0267t;
        this.b = b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof T0)) {
            return false;
        }
        T0 t0 = (T0) obj;
        return Intrinsics.b(this.a, t0.a) && Intrinsics.b(this.b, t0.b);
    }

    public final int hashCode() {
        return Integer.hashCode(0) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "VectorizedKeyframeSpecElementInfo(vectorValue=" + this.a + ", easing=" + this.b + ", arcMode=ArcMode(value=0))";
    }
}
