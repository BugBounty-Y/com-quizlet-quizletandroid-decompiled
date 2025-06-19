package androidx.compose.ui.graphics.vector;

import androidx.compose.animation.d0;

/* renamed from: androidx.compose.ui.graphics.vector.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0871j extends C {
    public final float c;
    public final float d;
    public final float e;
    public final boolean f;
    public final boolean g;
    public final float h;
    public final float i;

    public C0871j(float f, float f2, float f3, boolean z, boolean z2, float f4, float f5) {
        super(3);
        this.c = f;
        this.d = f2;
        this.e = f3;
        this.f = z;
        this.g = z2;
        this.h = f4;
        this.i = f5;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0871j)) {
            return false;
        }
        C0871j c0871j = (C0871j) obj;
        return Float.compare(this.c, c0871j.c) == 0 && Float.compare(this.d, c0871j.d) == 0 && Float.compare(this.e, c0871j.e) == 0 && this.f == c0871j.f && this.g == c0871j.g && Float.compare(this.h, c0871j.h) == 0 && Float.compare(this.i, c0871j.i) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.i) + android.support.v4.media.session.a.b(d0.g(d0.g(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.c) * 31, this.d, 31), this.e, 31), 31, this.f), 31, this.g), this.h, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ArcTo(horizontalEllipseRadius=");
        sb.append(this.c);
        sb.append(", verticalEllipseRadius=");
        sb.append(this.d);
        sb.append(", theta=");
        sb.append(this.e);
        sb.append(", isMoreThanHalf=");
        sb.append(this.f);
        sb.append(", isPositiveArc=");
        sb.append(this.g);
        sb.append(", arcStartX=");
        sb.append(this.h);
        sb.append(", arcStartY=");
        return android.support.v4.media.session.a.p(sb, this.i, ')');
    }
}
