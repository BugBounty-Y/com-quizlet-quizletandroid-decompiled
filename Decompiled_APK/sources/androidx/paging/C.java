package androidx.paging;

/* loaded from: classes.dex */
public final class C extends E {
    public static final C b = new C(false);

    public final boolean equals(Object obj) {
        if (obj instanceof C) {
            return this.a == ((C) obj).a;
        }
        return false;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.u(new StringBuilder("Loading(endOfPaginationReached="), this.a, ')');
    }
}
