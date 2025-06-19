package androidx.paging;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.paging.y, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1350y {
    public final int a;
    public final k1 b;

    public C1350y(int i, k1 hint) {
        Intrinsics.checkNotNullParameter(hint, "hint");
        this.a = i;
        this.b = hint;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C1350y)) {
            return false;
        }
        C1350y c1350y = (C1350y) obj;
        return this.a == c1350y.a && Intrinsics.b(this.b, c1350y.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "GenerationalViewportHint(generationId=" + this.a + ", hint=" + this.b + ')';
    }
}
