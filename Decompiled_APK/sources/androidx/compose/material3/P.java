package androidx.compose.material3;

/* loaded from: classes.dex */
public final class P {
    public final float a;
    public final float b;
    public final float c;
    public final float d;
    public final float e;

    public P(float f, float f2, float f3, float f4, float f5) {
        this.a = f;
        this.b = f2;
        this.c = f3;
        this.d = f4;
        this.e = f5;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || !(obj instanceof P)) {
            return false;
        }
        P p = (P) obj;
        return androidx.compose.ui.unit.e.a(this.a, p.a) && androidx.compose.ui.unit.e.a(this.b, p.b) && androidx.compose.ui.unit.e.a(this.c, p.c) && androidx.compose.ui.unit.e.a(this.d, p.d) && androidx.compose.ui.unit.e.a(this.e, p.e);
    }

    public final int hashCode() {
        return Float.hashCode(this.e) + android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31), this.c, 31), this.d, 31);
    }
}
