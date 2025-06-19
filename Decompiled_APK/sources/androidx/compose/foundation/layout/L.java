package androidx.compose.foundation.layout;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class L extends AbstractC0382e {
    public final androidx.compose.ui.g h;

    public L(androidx.compose.ui.g gVar) {
        this.h = gVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof L) && Intrinsics.b(this.h, ((L) obj).h);
    }

    @Override // androidx.compose.foundation.layout.AbstractC0382e
    public final int g(int i, androidx.compose.ui.unit.k kVar, androidx.compose.ui.layout.W w, int i2) {
        return this.h.a(0, i, kVar);
    }

    public final int hashCode() {
        return Float.hashCode(this.h.a);
    }

    public final String toString() {
        return "HorizontalCrossAxisAlignment(horizontal=" + this.h + ')';
    }
}
