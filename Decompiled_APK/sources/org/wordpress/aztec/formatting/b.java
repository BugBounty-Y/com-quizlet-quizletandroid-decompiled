package org.wordpress.aztec.formatting;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class b {
    public final int a;
    public int b = 0;
    public final int c;

    public b(int i, int i2) {
        this.a = i;
        this.c = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return this.a == bVar.a && this.b == bVar.b && this.c == bVar.c;
    }

    public final int hashCode() {
        return Integer.hashCode(this.c) + d0.b(this.b, Integer.hashCode(this.a) * 31, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("HeadingStyle(fontSize=");
        sb.append(this.a);
        sb.append(", fontSizeModifier=");
        sb.append(this.b);
        sb.append(", fontColor=");
        return android.support.v4.media.session.a.q(sb, this.c, ')');
    }
}
