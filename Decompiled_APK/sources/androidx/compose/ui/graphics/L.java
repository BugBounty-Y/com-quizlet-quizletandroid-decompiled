package androidx.compose.ui.graphics;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L extends N {
    public final androidx.compose.ui.geometry.c a;

    public L(androidx.compose.ui.geometry.c cVar) {
        this.a = cVar;
    }

    @Override // androidx.compose.ui.graphics.N
    public final androidx.compose.ui.geometry.c a() {
        return this.a;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof L) {
            return Intrinsics.b(this.a, ((L) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }
}
