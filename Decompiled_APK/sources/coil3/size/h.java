package coil3.size;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class h {
    public static final h c;
    public final c a;
    public final c b;

    static {
        b bVar = b.a;
        c = new h(bVar, bVar);
    }

    public h(c cVar, c cVar2) {
        this.a = cVar;
        this.b = cVar2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && Intrinsics.b(this.b, hVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Size(width=" + this.a + ", height=" + this.b + ')';
    }
}
