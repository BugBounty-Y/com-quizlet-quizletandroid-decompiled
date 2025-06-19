package org.wordpress.aztec.watchers;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.spans.H;

/* loaded from: classes3.dex */
public final class f {
    public final H a;
    public final int b;
    public final int c;

    public f(H span, int i, int i2) {
        Intrinsics.checkNotNullParameter(span, "span");
        this.a = span;
        this.b = i;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && this.b == fVar.b && this.c == fVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.b(this.b, this.a.hashCode() * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CarryOverSpan(span=");
        sb.append(this.a);
        sb.append(", start=");
        sb.append(this.b);
        sb.append(", end=");
        return android.support.v4.media.session.a.q(sb, this.c, ')');
    }
}
