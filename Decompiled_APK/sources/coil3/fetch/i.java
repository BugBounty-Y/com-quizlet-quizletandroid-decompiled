package coil3.fetch;

import coil3.decode.q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i implements e {
    public final q a;
    public final String b;
    public final coil3.decode.h c;

    public i(q qVar, String str, coil3.decode.h hVar) {
        this.a = qVar;
        this.b = str;
        this.c = hVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return Intrinsics.b(this.a, iVar.a) && Intrinsics.b(this.b, iVar.b) && this.c == iVar.c;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return this.c.hashCode() + ((iHashCode + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        return "SourceFetchResult(source=" + this.a + ", mimeType=" + this.b + ", dataSource=" + this.c + ')';
    }
}
