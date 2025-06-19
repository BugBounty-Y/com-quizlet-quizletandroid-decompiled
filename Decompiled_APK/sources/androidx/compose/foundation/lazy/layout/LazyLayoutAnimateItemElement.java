package androidx.compose.foundation.lazy.layout;

import androidx.compose.animation.core.C0253l0;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
public final class LazyLayoutAnimateItemElement extends androidx.compose.ui.node.T {
    public final androidx.compose.animation.core.D b;
    public final C0253l0 c;
    public final androidx.compose.animation.core.D d;

    public LazyLayoutAnimateItemElement(androidx.compose.animation.core.D d, C0253l0 c0253l0, androidx.compose.animation.core.D d2) {
        this.b = d;
        this.c = c0253l0;
        this.d = d2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof LazyLayoutAnimateItemElement)) {
            return false;
        }
        LazyLayoutAnimateItemElement lazyLayoutAnimateItemElement = (LazyLayoutAnimateItemElement) obj;
        return Intrinsics.b(this.b, lazyLayoutAnimateItemElement.b) && this.c.equals(lazyLayoutAnimateItemElement.c) && Intrinsics.b(this.d, lazyLayoutAnimateItemElement.d);
    }

    public final int hashCode() {
        androidx.compose.animation.core.D d = this.b;
        int iHashCode = (this.c.hashCode() + ((d == null ? 0 : d.hashCode()) * 31)) * 31;
        androidx.compose.animation.core.D d2 = this.d;
        return iHashCode + (d2 != null ? d2.hashCode() : 0);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        C0441m c0441m = new C0441m();
        c0441m.n = this.b;
        c0441m.o = this.c;
        c0441m.p = this.d;
        return c0441m;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        C0441m c0441m = (C0441m) pVar;
        c0441m.n = this.b;
        c0441m.o = this.c;
        c0441m.p = this.d;
    }

    public final String toString() {
        return "LazyLayoutAnimateItemElement(fadeInSpec=" + this.b + ", placementSpec=" + this.c + ", fadeOutSpec=" + this.d + ')';
    }
}
