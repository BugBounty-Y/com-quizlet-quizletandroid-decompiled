package androidx.compose.ui.graphics.vector;

/* loaded from: classes.dex */
public final class x extends C {
    public final float c;
    public final float d;
    public final float e;
    public final float f;

    public x(float f, float f2, float f3, float f4) {
        super(1);
        this.c = f;
        this.d = f2;
        this.e = f3;
        this.f = f4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof x)) {
            return false;
        }
        x xVar = (x) obj;
        return Float.compare(this.c, xVar.c) == 0 && Float.compare(this.d, xVar.d) == 0 && Float.compare(this.e, xVar.e) == 0 && Float.compare(this.f, xVar.f) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.f) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.c) * 31, this.d, 31), this.e, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RelativeQuadTo(dx1=");
        sb.append(this.c);
        sb.append(", dy1=");
        sb.append(this.d);
        sb.append(", dx2=");
        sb.append(this.e);
        sb.append(", dy2=");
        return android.support.v4.media.session.a.p(sb, this.f, ')');
    }
}
