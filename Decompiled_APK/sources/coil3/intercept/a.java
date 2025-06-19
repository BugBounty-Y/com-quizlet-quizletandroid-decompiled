package coil3.intercept;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a {
    public final coil3.j a;
    public final boolean b;
    public final coil3.decode.h c;
    public final String d;

    public a(coil3.j jVar, boolean z, coil3.decode.h hVar, String str) {
        this.a = jVar;
        this.b = z;
        this.c = hVar;
        this.d = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b && this.c == aVar.c && Intrinsics.b(this.d, aVar.d);
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + d0.g(this.a.hashCode() * 31, 31, this.b)) * 31;
        String str = this.d;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExecuteResult(image=");
        sb.append(this.a);
        sb.append(", isSampled=");
        sb.append(this.b);
        sb.append(", dataSource=");
        sb.append(this.c);
        sb.append(", diskCacheKey=");
        return d0.r(sb, this.d, ')');
    }
}
