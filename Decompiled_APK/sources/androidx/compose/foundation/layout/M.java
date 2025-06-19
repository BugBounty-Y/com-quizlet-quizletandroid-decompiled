package androidx.compose.foundation.layout;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class M extends AbstractC0382e {
    public final androidx.compose.ui.h h;

    public M(androidx.compose.ui.h hVar) {
        this.h = hVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof M) && Intrinsics.b(this.h, ((M) obj).h);
    }

    @Override // androidx.compose.foundation.layout.AbstractC0382e
    public final int g(int i, androidx.compose.ui.unit.k kVar, androidx.compose.ui.layout.W w, int i2) {
        return this.h.a(0, i);
    }

    public final int hashCode() {
        return Float.hashCode(this.h.a);
    }

    public final String toString() {
        return "VerticalCrossAxisAlignment(vertical=" + this.h + ')';
    }
}
