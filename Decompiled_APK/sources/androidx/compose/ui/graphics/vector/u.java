package androidx.compose.ui.graphics.vector;

/* loaded from: classes.dex */
public final class u extends C {
    public final float c;

    public u(float f) {
        super(3);
        this.c = f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof u) && Float.compare(this.c, ((u) obj).c) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.c);
    }

    public final String toString() {
        return android.support.v4.media.session.a.p(new StringBuilder("RelativeHorizontalTo(dx="), this.c, ')');
    }
}
