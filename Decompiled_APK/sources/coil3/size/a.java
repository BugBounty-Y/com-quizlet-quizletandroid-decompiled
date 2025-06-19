package coil3.size;

/* loaded from: classes.dex */
public final class a implements c {
    public final int a;

    public final boolean equals(Object obj) {
        if (obj instanceof a) {
            return this.a == ((a) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("Pixels(px="), this.a, ')');
    }
}
