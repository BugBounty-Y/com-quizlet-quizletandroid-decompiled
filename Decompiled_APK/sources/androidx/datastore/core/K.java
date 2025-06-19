package androidx.datastore.core;

import java.util.concurrent.atomic.AtomicInteger;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.channels.ClosedSendChannelException;

/* loaded from: classes.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public /* synthetic */ Object k;
    public final /* synthetic */ P l;
    public final /* synthetic */ Function2 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(P p, Function2 function2, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.l = p;
        this.m = function2;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        K k = new K(this.l, this.m, hVar);
        k.k = obj;
        return k;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
            return obj;
        }
        androidx.glance.appwidget.protobuf.Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.k;
        kotlinx.coroutines.r rVarB = kotlinx.coroutines.E.b();
        P p = this.l;
        b0 b0Var = new b0(this.m, rVarB, p.h.q(), c.getCoroutineContext());
        com.quizlet.data.repository.explanations.question.a aVar2 = p.l;
        Object objO = ((kotlinx.coroutines.channels.h) aVar2.c).o(b0Var);
        if (objO instanceof kotlinx.coroutines.channels.m) {
            Throwable thA = kotlinx.coroutines.channels.o.a(objO);
            if (thA == null) {
                throw new ClosedSendChannelException("Channel was closed normally");
            }
            throw thA;
        }
        if (objO instanceof kotlinx.coroutines.channels.n) {
            throw new IllegalStateException("Check failed.");
        }
        if (((AtomicInteger) ((androidx.appcompat.app.Q) aVar2.d).a).getAndIncrement() == 0) {
            kotlinx.coroutines.E.A((kotlinx.coroutines.C) aVar2.a, null, null, new g0(aVar2, null), 3);
        }
        this.j = 1;
        Object objW = rVarB.w(this);
        return objW == aVar ? aVar : objW;
    }
}
