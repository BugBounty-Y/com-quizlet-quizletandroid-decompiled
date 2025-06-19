package androidx.compose.ui;

/* loaded from: classes.dex */
public final class h {
    public final float a;

    public h(float f) {
        this.a = f;
    }

    public final int a(int i, int i2) {
        return Math.round((1 + this.a) * ((i2 - i) / 2.0f));
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && Float.compare(this.a, ((h) obj).a) == 0;
    }

    public final int hashCode() {
        return Float.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.p(new StringBuilder("Vertical(bias="), this.a, ')');
    }
}
