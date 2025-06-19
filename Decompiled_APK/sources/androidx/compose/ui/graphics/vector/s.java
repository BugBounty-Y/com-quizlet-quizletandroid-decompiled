package androidx.compose.ui.graphics.vector;

import androidx.compose.animation.d0;

/* loaded from: classes.dex */
public final class s extends C {
    public final float c;
    public final float d;
    public final float e;
    public final boolean f;
    public final boolean g;
    public final float h;
    public final float i;

    public s(float f, float f2, float f3, boolean z, boolean z2, float f4, float f5) {
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
        if (!(obj instanceof s)) {
            return false;
        }
        s sVar = (s) obj;
        return Float.compare(this.c, sVar.c) == 0 && Float.compare(this.d, sVar.d) == 0 && Float.compare(this.e, sVar.e) == 0 && this.f == sVar.f && this.g == sVar.g && Float.compare(this.h, sVar.h) == 0 && Float.compare(this.i, sVar.i) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.i) + android.support.v4.media.session.a.b(d0.g(d0.g(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.c) * 31, this.d, 31), this.e, 31), 31, this.f), 31, this.g), this.h, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RelativeArcTo(horizontalEllipseRadius=");
        sb.append(this.c);
        sb.append(", verticalEllipseRadius=");
        sb.append(this.d);
        sb.append(", theta=");
        sb.append(this.e);
        sb.append(", isMoreThanHalf=");
        sb.append(this.f);
        sb.append(", isPositiveArc=");
        sb.append(this.g);
        sb.append(", arcStartDx=");
        sb.append(this.h);
        sb.append(", arcStartDy=");
        return android.support.v4.media.session.a.p(sb, this.i, ')');
    }
}
