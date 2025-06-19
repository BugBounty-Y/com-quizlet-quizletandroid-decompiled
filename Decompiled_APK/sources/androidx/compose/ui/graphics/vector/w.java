package androidx.compose.ui.graphics.vector;

/* loaded from: classes.dex */
public final class w extends C {
    public final float c;
    public final float d;

    public w(float f, float f2) {
        super(3);
        this.c = f;
        this.d = f2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof w)) {
            return false;
        }
        w wVar = (w) obj;
        return Float.compare(this.c, wVar.c) == 0 && Float.compare(this.d, wVar.d) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.d) + (Float.hashCode(this.c) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("RelativeMoveTo(dx=");
        sb.append(this.c);
        sb.append(", dy=");
        return android.support.v4.media.session.a.p(sb, this.d, ')');
    }
}
