package coil3.request;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class o implements j {
    public final coil3.j a;
    public final g b;
    public final coil3.decode.h c;
    public final coil3.memory.a d;
    public final String e;
    public final boolean f;
    public final boolean g;

    public o(coil3.j jVar, g gVar, coil3.decode.h hVar, coil3.memory.a aVar, String str, boolean z, boolean z2) {
        this.a = jVar;
        this.b = gVar;
        this.c = hVar;
        this.d = aVar;
        this.e = str;
        this.f = z;
        this.g = z2;
    }

    @Override // coil3.request.j
    public final g b() {
        return this.b;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return Intrinsics.b(this.a, oVar.a) && Intrinsics.b(this.b, oVar.b) && this.c == oVar.c && Intrinsics.b(this.d, oVar.d) && Intrinsics.b(this.e, oVar.e) && this.f == oVar.f && this.g == oVar.g;
    }

    public final int hashCode() {
        int iHashCode = (this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31;
        coil3.memory.a aVar = this.d;
        int iHashCode2 = (iHashCode + (aVar == null ? 0 : aVar.hashCode())) * 31;
        String str = this.e;
        return Boolean.hashCode(this.g) + d0.g((iHashCode2 + (str != null ? str.hashCode() : 0)) * 31, 31, this.f);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("SuccessResult(image=");
        sb.append(this.a);
        sb.append(", request=");
        sb.append(this.b);
        sb.append(", dataSource=");
        sb.append(this.c);
        sb.append(", memoryCacheKey=");
        sb.append(this.d);
        sb.append(", diskCacheKey=");
        sb.append(this.e);
        sb.append(", isSampled=");
        sb.append(this.f);
        sb.append(", isPlaceholderCached=");
        return android.support.v4.media.session.a.u(sb, this.g, ')');
    }
}
