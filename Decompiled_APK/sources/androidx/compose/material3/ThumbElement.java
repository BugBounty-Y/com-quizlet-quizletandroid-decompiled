package androidx.compose.material3;

import androidx.compose.animation.core.AbstractC0240f;
import androidx.compose.ui.node.AbstractC0910f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes.dex */
final class ThumbElement extends androidx.compose.ui.node.T {
    public final androidx.compose.foundation.interaction.l b;
    public final boolean c;

    public ThumbElement(androidx.compose.foundation.interaction.l lVar, boolean z) {
        this.b = lVar;
        this.c = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof ThumbElement)) {
            return false;
        }
        ThumbElement thumbElement = (ThumbElement) obj;
        return Intrinsics.b(this.b, thumbElement.b) && this.c == thumbElement.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + (this.b.hashCode() * 31);
    }

    @Override // androidx.compose.ui.node.T
    public final androidx.compose.ui.p l() {
        U4 u4 = new U4();
        u4.n = this.b;
        u4.o = this.c;
        u4.s = Float.NaN;
        u4.t = Float.NaN;
        return u4;
    }

    @Override // androidx.compose.ui.node.T
    public final void n(androidx.compose.ui.p pVar) {
        U4 u4 = (U4) pVar;
        u4.n = this.b;
        boolean z = u4.o;
        boolean z2 = this.c;
        if (z != z2) {
            AbstractC0910f.o(u4);
        }
        u4.o = z2;
        if (u4.r == null && !Float.isNaN(u4.t)) {
            u4.r = AbstractC0240f.a(u4.t);
        }
        if (u4.q != null || Float.isNaN(u4.s)) {
            return;
        }
        u4.q = AbstractC0240f.a(u4.s);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ThumbElement(interactionSource=");
        sb.append(this.b);
        sb.append(", checked=");
        return android.support.v4.media.session.a.u(sb, this.c, ')');
    }
}
