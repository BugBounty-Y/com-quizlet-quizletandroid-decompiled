package androidx.compose.ui.graphics.vector;

/* loaded from: classes.dex */
public final class m extends C {
    public final float c;

    public m(float f) {
        super(3);
        this.c = f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Float.compare(this.c, ((m) obj).c) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.c);
    }

    public final String toString() {
        return android.support.v4.media.session.a.p(new StringBuilder("HorizontalTo(x="), this.c, ')');
    }
}
