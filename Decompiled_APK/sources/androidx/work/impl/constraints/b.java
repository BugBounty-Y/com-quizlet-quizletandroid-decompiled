package androidx.work.impl.constraints;

/* loaded from: classes.dex */
public final class b extends c {
    public final int a;

    public b(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && this.a == ((b) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.q(new StringBuilder("ConstraintsNotMet(reason="), this.a, ')');
    }
}
