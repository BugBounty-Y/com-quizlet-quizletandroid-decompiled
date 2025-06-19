package coil3.decode;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class i {
    public final coil3.j a;
    public final boolean b;

    public i(coil3.j jVar, boolean z) {
        this.a = jVar;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return Intrinsics.b(this.a, iVar.a) && this.b == iVar.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DecodeResult(image=");
        sb.append(this.a);
        sb.append(", isSampled=");
        return android.support.v4.media.session.a.u(sb, this.b, ')');
    }
}
