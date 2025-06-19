package androidx.compose.ui.graphics.vector;

/* loaded from: classes.dex */
public final class r extends C {
    public final float c;
    public final float d;

    public r(float f, float f2) {
        super(1);
        this.c = f;
        this.d = f2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return Float.compare(this.c, rVar.c) == 0 && Float.compare(this.d, rVar.d) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + (Float.hashCode(this.c) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ReflectiveQuadTo(x=");
        sb.append(this.c);
        sb.append(", y=");
        return android.support.v4.media.session.a.p(sb, this.d, ')');
    }
}
