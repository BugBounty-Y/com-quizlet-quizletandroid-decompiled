package org.wordpress.aztec.formatting;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class e {
    public final int a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;

    public e(int i, int i2, int i3, int i4, int i5) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
        this.e = i5;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return this.a == eVar.a && this.b == eVar.b && this.c == eVar.c && this.d == eVar.d && this.e == eVar.e;
    }

    public final int hashCode() {
        return Integer.hashCode(this.e) + d0.b(this.d, d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ListStyle(indicatorColor=");
        sb.append(this.a);
        sb.append(", indicatorMargin=");
        sb.append(this.b);
        sb.append(", indicatorPadding=");
        sb.append(this.c);
        sb.append(", indicatorWidth=");
        sb.append(this.d);
        sb.append(", verticalPadding=");
        return android.support.v4.media.session.a.q(sb, this.e, ')');
    }
}
