package androidx.compose.foundation;

import androidx.compose.ui.graphics.AbstractC0857q;
import androidx.compose.ui.graphics.C0861v;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class BackgroundElement extends androidx.compose.ui.node.T {
    public final long b;
    public final AbstractC0857q c;
    public final float d;
    public final androidx.compose.ui.graphics.V e;

    public BackgroundElement(long j, androidx.compose.ui.graphics.I i, androidx.compose.ui.graphics.V v, int i2) {
        j = (i2 & 1) != 0 ? C0861v.g : j;
        i = (i2 & 2) != 0 ? null : i;
        this.b = j;
        this.c = i;
        this.d = 1.0f;
        this.e = v;
    }

    public final boolean equals(Object obj) {
        BackgroundElement backgroundElement = obj instanceof BackgroundElement ? (BackgroundElement) obj : null;
        return backgroundElement != null && C0861v.c(this.b, backgroundElement.b) && Intrinsics.b(this.c, backgroundElement.c) && this.d == backgroundElement.d && Intrinsics.b(this.e, backgroundElement.e);
    }

    public final int hashCode() {
        int i = C0861v.h;
        kotlin.C c = kotlin.D.b;
        int iHashCode = Long.hashCode(this.b) * 31;
        AbstractC0857q abstractC0857q = this.c;
        return this.e.hashCode() + android.support.v4.media.session.a.b((iHashCode + (abstractC0857q != null ? abstractC0857q.hashCode() : 0)) * 31, this.d, 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        r rVar = new r();
        rVar.n = this.b;
        rVar.o = this.c;
        rVar.p = this.d;
        rVar.q = this.e;
        rVar.r = 9205357640488583168L;
        return rVar;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        r rVar = (r) pVar;
        rVar.n = this.b;
        rVar.o = this.c;
        rVar.p = this.d;
        rVar.q = this.e;
    }
}
