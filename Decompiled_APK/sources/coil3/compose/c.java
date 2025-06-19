package coil3.compose;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c {
    public final coil3.m a;
    public final coil3.request.g b;
    public final b c;

    public c(coil3.m mVar, coil3.request.g gVar, b bVar) {
        this.a = mVar;
        this.b = gVar;
        this.c = bVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        if (!Intrinsics.b(this.a, cVar.a)) {
            return false;
        }
        b bVar = cVar.c;
        b bVar2 = this.c;
        return Intrinsics.b(bVar2, bVar) && bVar2.a(this.b, cVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        b bVar = this.c;
        return bVar.b(this.b) + ((bVar.hashCode() + iHashCode) * 31);
    }

    public final String toString() {
        return "Input(imageLoader=" + this.a + ", request=" + this.b + ", modelEqualityDelegate=" + this.c + ')';
    }
}
