package org.wordpress.aztec.formatting;

import androidx.compose.animation.d0;

/* loaded from: classes3.dex */
public final class g {
    public final int a;
    public final float b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;
    public int i;

    public g(int i, float f, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        this.a = i;
        this.b = f;
        this.c = i2;
        this.d = i3;
        this.e = i4;
        this.f = i5;
        this.g = i6;
        this.h = i7;
        this.i = i8;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && Float.compare(this.b, gVar.b) == 0 && this.c == gVar.c && this.d == gVar.d && this.e == gVar.e && this.f == gVar.f && this.g == gVar.g && this.h == gVar.h && this.i == gVar.i;
    }

    public final int hashCode() {
        return Integer.hashCode(this.i) + d0.b(this.h, d0.b(this.g, d0.b(this.f, d0.b(this.e, d0.b(this.d, d0.b(this.c, android.support.v4.media.session.a.b(Integer.hashCode(this.a) * 31, this.b, 31), 31), 31), 31), 31), 31), 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PreformatStyle(preformatBackground=");
        sb.append(this.a);
        sb.append(", preformatBackgroundAlpha=");
        sb.append(this.b);
        sb.append(", preformatColor=");
        sb.append(this.c);
        sb.append(", verticalPadding=");
        sb.append(this.d);
        sb.append(", leadingMargin=");
        sb.append(this.e);
        sb.append(", preformatBorderColor=");
        sb.append(this.f);
        sb.append(", preformatBorderRadius=");
        sb.append(this.g);
        sb.append(", preformatBorderThickness=");
        sb.append(this.h);
        sb.append(", preformatTextSize=");
        return android.support.v4.media.session.a.q(sb, this.i, ')');
    }
}
