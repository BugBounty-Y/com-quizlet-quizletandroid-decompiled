package org.wordpress.aztec.formatting;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.spans.D;

/* loaded from: classes3.dex */
public final class m {
    public final D a;
    public final int b;
    public final int c;
    public final int d;

    public m(D span, int i, int i2, int i3) {
        Intrinsics.checkNotNullParameter(span, "span");
        this.a = span;
        this.b = i;
        this.c = i2;
        this.d = i3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof m)) {
            return false;
        }
        m mVar = (m) obj;
        return Intrinsics.b(this.a, mVar.a) && this.b == mVar.b && this.c == mVar.c && this.d == mVar.d;
    }

    public final int hashCode() {
        return Integer.hashCode(this.d) + d0.b(this.c, d0.b(this.b, this.a.hashCode() * 31, 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SpanData(span=");
        sb.append(this.a);
        sb.append(", spanStart=");
        sb.append(this.b);
        sb.append(", spanEnd=");
        sb.append(this.c);
        sb.append(", spanFlags=");
        return android.support.v4.media.session.a.q(sb, this.d, ')');
    }
}
