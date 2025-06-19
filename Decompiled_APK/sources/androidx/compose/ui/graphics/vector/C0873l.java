package androidx.compose.ui.graphics.vector;

/* renamed from: androidx.compose.ui.graphics.vector.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0873l extends C {
    public final float c;
    public final float d;
    public final float e;
    public final float f;
    public final float g;
    public final float h;

    public C0873l(float f, float f2, float f3, float f4, float f5, float f6) {
        super(2);
        this.c = f;
        this.d = f2;
        this.e = f3;
        this.f = f4;
        this.g = f5;
        this.h = f6;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0873l)) {
            return false;
        }
        C0873l c0873l = (C0873l) obj;
        return Float.compare(this.c, c0873l.c) == 0 && Float.compare(this.d, c0873l.d) == 0 && Float.compare(this.e, c0873l.e) == 0 && Float.compare(this.f, c0873l.f) == 0 && Float.compare(this.g, c0873l.g) == 0 && Float.compare(this.h, c0873l.h) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.h) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.c) * 31, this.d, 31), this.e, 31), this.f, 31), this.g, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CurveTo(x1=");
        sb.append(this.c);
        sb.append(", y1=");
        sb.append(this.d);
        sb.append(", x2=");
        sb.append(this.e);
        sb.append(", y2=");
        sb.append(this.f);
        sb.append(", x3=");
        sb.append(this.g);
        sb.append(", y3=");
        return android.support.v4.media.session.a.p(sb, this.h, ')');
    }
}
