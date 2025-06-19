package coil3.request;

import android.content.Context;
import java.util.Map;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class g {
    public final Context a;
    public final Object b;
    public final androidx.work.impl.model.l c;
    public final Map d;
    public final okio.n e;
    public final CoroutineContext f;
    public final CoroutineContext g;
    public final CoroutineContext h;
    public final b i;
    public final b j;
    public final b k;
    public final Function1 l;
    public final Function1 m;
    public final Function1 n;
    public final coil3.size.i o;
    public final coil3.size.g p;
    public final coil3.size.d q;
    public final coil3.i r;
    public final f s;
    public final e t;

    public g(Context context, Object obj, androidx.work.impl.model.l lVar, Map map, okio.n nVar, CoroutineContext coroutineContext, CoroutineContext coroutineContext2, CoroutineContext coroutineContext3, b bVar, b bVar2, b bVar3, Function1 function1, Function1 function12, Function1 function13, coil3.size.i iVar, coil3.size.g gVar, coil3.size.d dVar, coil3.i iVar2, f fVar, e eVar) {
        this.a = context;
        this.b = obj;
        this.c = lVar;
        this.d = map;
        this.e = nVar;
        this.f = coroutineContext;
        this.g = coroutineContext2;
        this.h = coroutineContext3;
        this.i = bVar;
        this.j = bVar2;
        this.k = bVar3;
        this.l = function1;
        this.m = function12;
        this.n = function13;
        this.o = iVar;
        this.p = gVar;
        this.q = dVar;
        this.r = iVar2;
        this.s = fVar;
        this.t = eVar;
    }

    public static d a(g gVar) {
        Context context = gVar.a;
        gVar.getClass();
        return new d(gVar, context);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && this.b.equals(gVar.b) && Intrinsics.b(this.c, gVar.c) && this.d.equals(gVar.d) && Intrinsics.b(this.e, gVar.e) && Intrinsics.b(this.f, gVar.f) && Intrinsics.b(this.g, gVar.g) && Intrinsics.b(this.h, gVar.h) && this.i == gVar.i && this.j == gVar.j && this.k == gVar.k && Intrinsics.b(this.l, gVar.l) && Intrinsics.b(this.m, gVar.m) && Intrinsics.b(this.n, gVar.n) && Intrinsics.b(this.o, gVar.o) && this.p == gVar.p && this.q == gVar.q && Intrinsics.b(this.r, gVar.r) && this.s.equals(gVar.s) && Intrinsics.b(this.t, gVar.t);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        androidx.work.impl.model.l lVar = this.c;
        return this.t.hashCode() + ((this.s.hashCode() + assistantMode.refactored.a.d((this.q.hashCode() + ((this.p.hashCode() + ((this.o.hashCode() + ((this.n.hashCode() + ((this.m.hashCode() + ((this.l.hashCode() + ((this.k.hashCode() + ((this.j.hashCode() + ((this.i.hashCode() + ((this.h.hashCode() + ((this.g.hashCode() + ((this.f.hashCode() + ((this.e.hashCode() + assistantMode.refactored.a.d((iHashCode + (lVar == null ? 0 : lVar.hashCode())) * 29791, 961, this.d)) * 29791)) * 31)) * 31)) * 31)) * 31)) * 31)) * 961)) * 31)) * 31)) * 31)) * 31)) * 31)) * 31, 31, this.r.a)) * 31);
    }

    public final String toString() {
        return "ImageRequest(context=" + this.a + ", data=" + this.b + ", target=" + this.c + ", listener=null, memoryCacheKey=null, memoryCacheKeyExtras=" + this.d + ", diskCacheKey=null, fileSystem=" + this.e + ", fetcherFactory=null, decoderFactory=null, interceptorCoroutineContext=" + this.f + ", fetcherCoroutineContext=" + this.g + ", decoderCoroutineContext=" + this.h + ", memoryCachePolicy=" + this.i + ", diskCachePolicy=" + this.j + ", networkCachePolicy=" + this.k + ", placeholderMemoryCacheKey=null, placeholderFactory=" + this.l + ", errorFactory=" + this.m + ", fallbackFactory=" + this.n + ", sizeResolver=" + this.o + ", scale=" + this.p + ", precision=" + this.q + ", extras=" + this.r + ", defined=" + this.s + ", defaults=" + this.t + ')';
    }
}
