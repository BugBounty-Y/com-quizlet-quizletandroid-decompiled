package androidx.paging;

/* loaded from: classes.dex */
public final class D extends E {
    public static final D b = new D(true);
    public static final D c = new D(false);

    public final boolean equals(Object obj) {
        if (obj instanceof D) {
            return this.a == ((D) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.u(new StringBuilder("NotLoading(endOfPaginationReached="), this.a, ')');
    }
}
