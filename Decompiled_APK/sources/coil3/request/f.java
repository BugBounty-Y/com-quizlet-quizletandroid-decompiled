package coil3.request;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class f {
    public final kotlin.coroutines.n a;
    public final kotlin.coroutines.n b;
    public final kotlin.coroutines.n c;
    public final coil3.util.k d;
    public final coil3.util.k e;
    public final coil3.util.k f;
    public final coil3.size.i g;
    public final coil3.size.g h;
    public final coil3.size.d i;

    public f(kotlin.coroutines.n nVar, kotlin.coroutines.n nVar2, kotlin.coroutines.n nVar3, coil3.util.k kVar, coil3.util.k kVar2, coil3.util.k kVar3, coil3.size.i iVar, coil3.size.g gVar, coil3.size.d dVar) {
        this.a = nVar;
        this.b = nVar2;
        this.c = nVar3;
        this.d = kVar;
        this.e = kVar2;
        this.f = kVar3;
        this.g = iVar;
        this.h = gVar;
        this.i = dVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        fVar.getClass();
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b) && Intrinsics.b(this.c, fVar.c) && Intrinsics.b(this.d, fVar.d) && Intrinsics.b(this.e, fVar.e) && Intrinsics.b(this.f, fVar.f) && Intrinsics.b(this.g, fVar.g) && this.h == fVar.h && this.i == fVar.i;
    }

    public final int hashCode() {
        coil3.util.k kVar = this.d;
        int iHashCode = (kVar == null ? 0 : kVar.hashCode()) * 31;
        coil3.util.k kVar2 = this.e;
        int iHashCode2 = (iHashCode + (kVar2 == null ? 0 : kVar2.hashCode())) * 31;
        coil3.util.k kVar3 = this.f;
        int iHashCode3 = (iHashCode2 + (kVar3 == null ? 0 : kVar3.hashCode())) * 31;
        coil3.size.i iVar = this.g;
        int iHashCode4 = (iHashCode3 + (iVar == null ? 0 : iVar.hashCode())) * 31;
        coil3.size.g gVar = this.h;
        int iHashCode5 = (iHashCode4 + (gVar == null ? 0 : gVar.hashCode())) * 31;
        coil3.size.d dVar = this.i;
        return iHashCode5 + (dVar != null ? dVar.hashCode() : 0);
    }

    public final String toString() {
        return "Defined(fileSystem=null, interceptorCoroutineContext=" + this.a + ", fetcherCoroutineContext=" + this.b + ", decoderCoroutineContext=" + this.c + ", memoryCachePolicy=null, diskCachePolicy=null, networkCachePolicy=null, placeholderFactory=" + this.d + ", errorFactory=" + this.e + ", fallbackFactory=" + this.f + ", sizeResolver=" + this.g + ", scale=" + this.h + ", precision=" + this.i + ')';
    }
}
