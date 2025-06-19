package coil3.request;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class c implements j {
    public final coil3.j a;
    public final g b;
    public final Throwable c;

    public c(coil3.j jVar, g gVar, Throwable th) {
        this.a = jVar;
        this.b = gVar;
        this.c = th;
    }

    @Override // coil3.request.j
    public final g b() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return Intrinsics.b(this.a, cVar.a) && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c);
    }

    public final int hashCode() {
        coil3.j jVar = this.a;
        return this.c.hashCode() + ((this.b.hashCode() + ((jVar == null ? 0 : jVar.hashCode()) * 31)) * 31);
    }

    public final String toString() {
        return "ErrorResult(image=" + this.a + ", request=" + this.b + ", throwable=" + this.c + ')';
    }
}
