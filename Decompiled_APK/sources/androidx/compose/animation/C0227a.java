package androidx.compose.animation;

/* renamed from: androidx.compose.animation.a, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0227a {
    public final float a;
    public final float b;

    public C0227a(float f, float f2) {
        this.a = f;
        this.b = f2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C0227a)) {
            return false;
        }
        C0227a c0227a = (C0227a) obj;
        return Float.compare(this.a, c0227a.a) == 0 && Float.compare(this.b, c0227a.b) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.b) + (Float.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlingResult(distanceCoefficient=");
        sb.append(this.a);
        sb.append(", velocityCoefficient=");
        return android.support.v4.media.session.a.p(sb, this.b, ')');
    }
}
