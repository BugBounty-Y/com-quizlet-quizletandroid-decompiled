package androidx.compose.ui.graphics.vector;

/* loaded from: classes.dex */
public final class n extends C {
    public final float c;
    public final float d;

    public n(float f, float f2) {
        super(3);
        this.c = f;
        this.d = f2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Float.compare(this.c, nVar.c) == 0 && Float.compare(this.d, nVar.d) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + (Float.hashCode(this.c) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LineTo(x=");
        sb.append(this.c);
        sb.append(", y=");
        return android.support.v4.media.session.a.p(sb, this.d, ')');
    }
}
