package androidx.compose.animation.core;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class Q {
    public final Float a;
    public B b;

    public Q(Float f, B b) {
        this.a = f;
        this.b = b;
    }

    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof Q)) {
            return false;
        }
        Q q = (Q) obj;
        return q.a.equals(this.a) && Intrinsics.b(q.b, this.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + androidx.compose.animation.d0.b(0, this.a.hashCode() * 31, 31);
    }
}
