package androidx.compose.material.ripple;

/* loaded from: classes.dex */
public final class f {
    public final float a;
    public final float b;
    public final float c;
    public final float d;

    public f(float f, float f2, float f3, float f4) {
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return this.a == fVar.a && this.b == fVar.b && this.c == fVar.c && this.d == fVar.d;
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31), this.c, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RippleAlpha(draggedAlpha=");
        sb.append(this.a);
        sb.append(", focusedAlpha=");
        sb.append(this.b);
        sb.append(", hoveredAlpha=");
        sb.append(this.c);
        sb.append(", pressedAlpha=");
        return android.support.v4.media.session.a.p(sb, this.d, ')');
    }
}
