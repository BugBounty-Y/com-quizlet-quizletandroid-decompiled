package androidx.compose.ui.graphics.vector;

/* loaded from: classes.dex */
public final class o extends C {
    public final float c;
    public final float d;

    public o(float f, float f2) {
        super(3);
        this.c = f;
        this.d = f2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return Float.compare(this.c, oVar.c) == 0 && Float.compare(this.d, oVar.d) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + (Float.hashCode(this.c) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("MoveTo(x=");
        sb.append(this.c);
        sb.append(", y=");
        return android.support.v4.media.session.a.p(sb, this.d, ')');
    }
}
