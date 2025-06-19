package androidx.paging;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: androidx.paging.l, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1325l {
    public final E a;
    public final E b;
    public final E c;
    public final F d;
    public final F e;

    public C1325l(E refresh, E prepend, E append, F source, F f) {
        Intrinsics.checkNotNullParameter(refresh, "refresh");
        Intrinsics.checkNotNullParameter(prepend, "prepend");
        Intrinsics.checkNotNullParameter(append, "append");
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = refresh;
        this.b = prepend;
        this.c = append;
        this.d = source;
        this.e = f;
        if (source.e && f != null) {
            boolean z = f.e;
        }
        boolean z2 = source.d;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || C1325l.class != obj.getClass()) {
            return false;
        }
        C1325l c1325l = (C1325l) obj;
        return Intrinsics.b(this.a, c1325l.a) && Intrinsics.b(this.b, c1325l.b) && Intrinsics.b(this.c, c1325l.c) && Intrinsics.b(this.d, c1325l.d) && Intrinsics.b(this.e, c1325l.e);
    }

    public final int hashCode() {
        int iHashCode = (this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31;
        F f = this.e;
        return iHashCode + (f != null ? f.hashCode() : 0);
    }

    public final String toString() {
        return "CombinedLoadStates(refresh=" + this.a + ", prepend=" + this.b + ", append=" + this.c + ", source=" + this.d + ", mediator=" + this.e + ')';
    }
}
