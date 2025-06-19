package androidx.paging;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class F {
    public static final F f;
    public final E a;
    public final E b;
    public final E c;
    public final boolean d;
    public final boolean e;

    static {
        D d = D.c;
        f = new F(d, d, d);
    }

    public F(E refresh, E prepend, E append) {
        Intrinsics.checkNotNullParameter(refresh, "refresh");
        Intrinsics.checkNotNullParameter(prepend, "prepend");
        Intrinsics.checkNotNullParameter(append, "append");
        this.a = refresh;
        this.b = prepend;
        this.c = append;
        this.d = (refresh instanceof B) || (append instanceof B) || (prepend instanceof B);
        this.e = (refresh instanceof D) && (append instanceof D) && (prepend instanceof D);
    }

    public static F a(F f2, int i) {
        E append = D.c;
        E refresh = (i & 1) != 0 ? f2.a : append;
        E prepend = (i & 2) != 0 ? f2.b : append;
        if ((i & 4) != 0) {
            append = f2.c;
        }
        f2.getClass();
        Intrinsics.checkNotNullParameter(refresh, "refresh");
        Intrinsics.checkNotNullParameter(prepend, "prepend");
        Intrinsics.checkNotNullParameter(append, "append");
        return new F(refresh, prepend, append);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof F)) {
            return false;
        }
        F f2 = (F) obj;
        return Intrinsics.b(this.a, f2.a) && Intrinsics.b(this.b, f2.b) && Intrinsics.b(this.c, f2.c);
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "LoadStates(refresh=" + this.a + ", prepend=" + this.b + ", append=" + this.c + ')';
    }
}
