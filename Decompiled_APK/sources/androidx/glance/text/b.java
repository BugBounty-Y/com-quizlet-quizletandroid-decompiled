package androidx.glance.text;

/* loaded from: classes.dex */
public final class b {
    public final int a;

    public final boolean equals(Object obj) {
        if (obj instanceof b) {
            return this.a == ((b) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("FontWeight(value="), this.a, ')');
    }
}
