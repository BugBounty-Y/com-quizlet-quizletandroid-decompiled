package org.wordpress.aztec.formatting;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class h {
    public final int a;
    public final int b;
    public final int c;
    public final float d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;

    public h(int i, int i2, int i3, float f, int i4, int i5, int i6, int i7) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = f;
        this.e = i4;
        this.f = i5;
        this.g = i6;
        this.h = i7;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return this.a == hVar.a && this.b == hVar.b && this.c == hVar.c && Float.compare(this.d, hVar.d) == 0 && this.e == hVar.e && this.f == hVar.f && this.g == hVar.g && this.h == hVar.h;
    }

    public final int hashCode() {
        return Integer.hashCode(this.h) + d0.b(this.g, d0.b(this.f, d0.b(this.e, android.support.v4.media.session.a.b(d0.b(this.c, d0.b(this.b, Integer.hashCode(this.a) * 31, 31), 31), this.d, 31), 31), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("QuoteStyle(quoteBackground=");
        sb.append(this.a);
        sb.append(", quoteColor=");
        sb.append(this.b);
        sb.append(", quoteTextColor=");
        sb.append(this.c);
        sb.append(", quoteBackgroundAlpha=");
        sb.append(this.d);
        sb.append(", quoteMargin=");
        sb.append(this.e);
        sb.append(", quotePadding=");
        sb.append(this.f);
        sb.append(", quoteWidth=");
        sb.append(this.g);
        sb.append(", verticalPadding=");
        return android.support.v4.media.session.a.q(sb, this.h, ')');
    }
}
