package kotlin.ranges;

/* loaded from: classes3.dex */
public final class f {
    public final float a;
    public final float b;

    public f(float f, float f2) {
        this.a = f;
        this.b = f2;
    }

    public static boolean a(Float f, Float f2) {
        return f.floatValue() <= f2.floatValue();
    }

    public final boolean equals(Object obj) {
        if (!(obj instanceof f)) {
            return false;
        }
        float f = this.a;
        float f2 = this.b;
        if (f > f2) {
            f fVar = (f) obj;
            if (fVar.a > fVar.b) {
                return true;
            }
        }
        f fVar2 = (f) obj;
        return f == fVar2.a && f2 == fVar2.b;
    }

    public final int hashCode() {
        float f = this.a;
        float f2 = this.b;
        if (f > f2) {
            return -1;
        }
        return Float.hashCode(f2) + (Float.hashCode(f) * 31);
    }

    public final String toString() {
        return this.a + ".." + this.b;
    }
}
