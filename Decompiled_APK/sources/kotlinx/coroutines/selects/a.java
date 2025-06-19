package kotlinx.coroutines.selects;

import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.C4956o;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final /* synthetic */ class a extends C4956o implements kotlin.jvm.functions.c {
    public static final a a = new a(3, b.class, "register", "register(Lkotlinx/coroutines/selects/SelectInstance;Ljava/lang/Object;)V", 0);

    @Override // kotlin.jvm.functions.c
    public final Object invoke(Object obj, Object obj2, Object obj3) {
        b bVar = (b) obj;
        f fVar = (f) obj2;
        long j = bVar.a;
        if (j <= 0) {
            ((e) fVar).e = Unit.a;
        } else {
            com.skydoves.balloon.compose.a aVar = new com.skydoves.balloon.compose.a(7, fVar, bVar);
            Intrinsics.e(fVar, "null cannot be cast to non-null type kotlinx.coroutines.selects.SelectImplementation<*>");
            e eVar = (e) fVar;
            CoroutineContext coroutineContext = eVar.a;
            eVar.c = E.q(coroutineContext).i(j, aVar, coroutineContext);
        }
        return Unit.a;
    }
}
