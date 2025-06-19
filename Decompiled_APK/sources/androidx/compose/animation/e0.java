package androidx.compose.animation;

/* loaded from: classes.dex */
public final class e0 {
    public final float a;
    public final float b;
    public final long c;

    public e0(float f, float f2, long j) {
        this.a = f;
        this.b = f2;
        this.c = j;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e0)) {
            return false;
        }
        e0 e0Var = (e0) obj;
        return Float.compare(this.a, e0Var.a) == 0 && Float.compare(this.b, e0Var.b) == 0 && this.c == e0Var.c;
    }

    public final int hashCode() {
        return Long.hashCode(this.c) + android.support.v4.media.session.a.b(Float.hashCode(this.a) * 31, this.b, 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("FlingInfo(initialVelocity=");
        sb.append(this.a);
        sb.append(", distance=");
        sb.append(this.b);
        sb.append(", duration=");
        return d0.q(sb, this.c, ')');
    }
}
