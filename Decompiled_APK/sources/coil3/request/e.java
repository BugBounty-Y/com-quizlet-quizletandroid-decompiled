package coil3.request;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.O;
import okio.t;

/* loaded from: classes.dex */
public final class e {
    public static final e o;
    public final okio.n a;
    public final CoroutineContext b;
    public final CoroutineContext c;
    public final CoroutineContext d;
    public final b e;
    public final b f;
    public final b g;
    public final Function1 h;
    public final Function1 i;
    public final Function1 j;
    public final coil3.size.i k;
    public final coil3.size.g l;
    public final coil3.size.d m;
    public final coil3.i n;

    static {
        t tVar = okio.n.a;
        kotlin.coroutines.n nVar = kotlin.coroutines.n.a;
        kotlinx.coroutines.scheduling.e eVar = O.a;
        kotlinx.coroutines.scheduling.d dVar = kotlinx.coroutines.scheduling.d.b;
        b bVar = b.c;
        coil3.util.k kVar = coil3.util.k.a;
        o = new e(tVar, nVar, dVar, dVar, bVar, bVar, bVar, kVar, kVar, kVar, coil3.size.i.a, coil3.size.g.b, coil3.size.d.a, coil3.i.b);
    }

    public e(okio.n nVar, CoroutineContext coroutineContext, CoroutineContext coroutineContext2, CoroutineContext coroutineContext3, b bVar, b bVar2, b bVar3, Function1 function1, Function1 function12, Function1 function13, coil3.size.i iVar, coil3.size.g gVar, coil3.size.d dVar, coil3.i iVar2) {
        this.a = nVar;
        this.b = coroutineContext;
        this.c = coroutineContext2;
        this.d = coroutineContext3;
        this.e = bVar;
        this.f = bVar2;
        this.g = bVar3;
        this.h = function1;
        this.i = function12;
        this.j = function13;
        this.k = iVar;
        this.l = gVar;
        this.m = dVar;
        this.n = iVar2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b) && Intrinsics.b(this.c, eVar.c) && Intrinsics.b(this.d, eVar.d) && this.e == eVar.e && this.f == eVar.f && this.g == eVar.g && Intrinsics.b(this.h, eVar.h) && Intrinsics.b(this.i, eVar.i) && Intrinsics.b(this.j, eVar.j) && Intrinsics.b(this.k, eVar.k) && this.l == eVar.l && this.m == eVar.m && Intrinsics.b(this.n, eVar.n);
    }

    public final int hashCode() {
        return this.n.a.hashCode() + ((this.m.hashCode() + ((this.l.hashCode() + ((this.k.hashCode() + ((this.j.hashCode() + ((this.i.hashCode() + ((this.h.hashCode() + ((this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "Defaults(fileSystem=" + this.a + ", interceptorCoroutineContext=" + this.b + ", fetcherCoroutineContext=" + this.c + ", decoderCoroutineContext=" + this.d + ", memoryCachePolicy=" + this.e + ", diskCachePolicy=" + this.f + ", networkCachePolicy=" + this.g + ", placeholderFactory=" + this.h + ", errorFactory=" + this.i + ", fallbackFactory=" + this.j + ", sizeResolver=" + this.k + ", scale=" + this.l + ", precision=" + this.m + ", extras=" + this.n + ')';
    }
}
