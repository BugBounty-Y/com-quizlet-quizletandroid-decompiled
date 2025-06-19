package androidx.compose.ui.graphics.vector;

/* loaded from: classes.dex */
public final class v extends C {
    public final float c;
    public final float d;

    public v(float f, float f2) {
        super(3);
        this.c = f;
        this.d = f2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof v)) {
            return false;
        }
        v vVar = (v) obj;
        return Float.compare(this.c, vVar.c) == 0 && Float.compare(this.d, vVar.d) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + (Float.hashCode(this.c) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RelativeLineTo(dx=");
        sb.append(this.c);
        sb.append(", dy=");
        return android.support.v4.media.session.a.p(sb, this.d, ')');
    }
}
