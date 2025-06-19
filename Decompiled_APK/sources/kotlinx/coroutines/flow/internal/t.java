package kotlinx.coroutines.flow.internal;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class t extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.analytics.marketing.appsflyer.d k;
    public final /* synthetic */ CoroutineContext l;
    public final /* synthetic */ Object m;
    public final /* synthetic */ kotlinx.coroutines.channels.t n;
    public final /* synthetic */ InterfaceC5002j o;
    public final /* synthetic */ com.quizlet.qutils.coroutines.a p;
    public final /* synthetic */ C5027k0 q;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public t(com.quizlet.analytics.marketing.appsflyer.d dVar, CoroutineContext coroutineContext, Object obj, kotlinx.coroutines.channels.t tVar, InterfaceC5002j interfaceC5002j, com.quizlet.qutils.coroutines.a aVar, C5027k0 c5027k0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = dVar;
        this.l = coroutineContext;
        this.m = obj;
        this.n = tVar;
        this.o = interfaceC5002j;
        this.p = aVar;
        this.q = c5027k0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new t(this.k, this.l, this.m, this.n, this.o, this.p, this.q, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((t) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            s sVar = new s(this.l, this.m, this.n, this.o, this.p, this.q);
            this.j = 1;
            if (this.k.b(sVar, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
