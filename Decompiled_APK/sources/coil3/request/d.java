package coil3.request;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3473j;
import java.util.Map;
import kotlin.collections.V;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.O;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes.dex */
public final class d {
    public final Context a;
    public e b;
    public Object c;
    public androidx.work.impl.model.l d;
    public final Map e;
    public kotlin.coroutines.n f;
    public kotlin.coroutines.n g;
    public kotlin.coroutines.n h;
    public final coil3.util.k i;
    public final coil3.util.k j;
    public final coil3.util.k k;
    public coil3.size.i l;
    public coil3.size.g m;
    public coil3.size.d n;
    public final coil3.i o;

    public d(@NotNull Context context) {
        this.a = context;
        this.b = e.o;
        this.c = null;
        this.d = null;
        this.e = V.c();
        this.f = null;
        this.g = null;
        this.h = null;
        coil3.util.k kVar = coil3.util.k.a;
        this.i = kVar;
        this.j = kVar;
        this.k = kVar;
        this.l = null;
        this.m = null;
        this.n = null;
        this.o = coil3.i.b;
    }

    public final g a() {
        Map mapC;
        Object obj = this.c;
        if (obj == null) {
            obj = l.a;
        }
        Object obj2 = obj;
        androidx.work.impl.model.l lVar = this.d;
        Boolean bool = Boolean.FALSE;
        Map map = this.e;
        if (Intrinsics.b(map, bool)) {
            Intrinsics.e(map, "null cannot be cast to non-null type kotlin.collections.MutableMap<*, *>");
            mapC = AbstractC3473j.c(O.c(map));
        } else {
            if (!(map instanceof Map)) {
                throw new AssertionError();
            }
            mapC = map;
        }
        Map map2 = mapC;
        Intrinsics.e(map2, "null cannot be cast to non-null type kotlin.collections.Map<kotlin.String, kotlin.String>");
        e eVar = this.b;
        okio.n nVar = eVar.a;
        b bVar = eVar.e;
        b bVar2 = eVar.f;
        b bVar3 = eVar.g;
        CoroutineContext coroutineContext = this.f;
        if (coroutineContext == null) {
            coroutineContext = eVar.b;
        }
        CoroutineContext coroutineContext2 = coroutineContext;
        CoroutineContext coroutineContext3 = this.g;
        if (coroutineContext3 == null) {
            coroutineContext3 = eVar.c;
        }
        CoroutineContext coroutineContext4 = coroutineContext3;
        CoroutineContext coroutineContext5 = this.h;
        if (coroutineContext5 == null) {
            coroutineContext5 = eVar.d;
        }
        CoroutineContext coroutineContext6 = coroutineContext5;
        Function1 function1 = this.i;
        if (function1 == null) {
            function1 = eVar.h;
        }
        Function1 function12 = function1;
        Function1 function13 = this.j;
        if (function13 == null) {
            function13 = eVar.i;
        }
        Function1 function14 = function13;
        Function1 function15 = this.k;
        if (function15 == null) {
            function15 = eVar.j;
        }
        Function1 function16 = function15;
        coil3.size.i iVar = this.l;
        if (iVar == null) {
            iVar = eVar.k;
        }
        coil3.size.i iVar2 = iVar;
        coil3.size.g gVar = this.m;
        if (gVar == null) {
            gVar = eVar.l;
        }
        coil3.size.g gVar2 = gVar;
        coil3.size.d dVar = this.n;
        if (dVar == null) {
            dVar = eVar.m;
        }
        coil3.size.d dVar2 = dVar;
        coil3.i iVar3 = this.o;
        if (iVar3 == null) {
            throw new AssertionError();
        }
        return new g(this.a, obj2, lVar, map2, nVar, coroutineContext2, coroutineContext4, coroutineContext6, bVar, bVar2, bVar3, function12, function14, function16, iVar2, gVar2, dVar2, iVar3, new f(this.f, this.g, this.h, this.i, this.j, this.k, this.l, this.m, this.n), this.b);
    }

    public d(g gVar, Context context) {
        this.a = context;
        this.b = gVar.t;
        this.c = gVar.b;
        this.d = gVar.c;
        this.e = gVar.d;
        f fVar = gVar.s;
        this.f = fVar.a;
        this.g = fVar.b;
        this.h = fVar.c;
        this.i = fVar.d;
        this.j = fVar.e;
        this.k = fVar.f;
        this.l = fVar.g;
        this.m = fVar.h;
        this.n = fVar.i;
        this.o = gVar.r;
    }
}
