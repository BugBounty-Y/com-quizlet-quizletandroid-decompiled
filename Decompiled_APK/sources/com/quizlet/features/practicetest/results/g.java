package com.quizlet.features.practicetest.results;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.model.U0;
import com.quizlet.features.practicetest.results.data.o;
import com.quizlet.features.practicetest.results.data.p;
import com.quizlet.features.practicetest.results.data.q;
import com.quizlet.features.practicetest.results.data.r;
import com.quizlet.features.practicetest.results.data.s;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class g extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function2 k;
    public final /* synthetic */ kotlin.jvm.functions.d l;
    public final /* synthetic */ Function2 m;
    public final /* synthetic */ Function2 n;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(Function2 function2, kotlin.jvm.functions.d dVar, Function2 function22, Function2 function23, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = function2;
        this.l = dVar;
        this.m = function22;
        this.n = function23;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        g gVar = new g(this.k, this.l, this.m, this.n, hVar);
        gVar.j = obj;
        return gVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((g) create((s) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        s sVar = (s) this.j;
        if (sVar instanceof o) {
            o oVar = (o) sVar;
            this.k.invoke(oVar.a, oVar.b);
        } else if (sVar instanceof r) {
            r rVar = (r) sVar;
            this.l.invoke(rVar.a, rVar.b, U0.d, rVar.c);
        } else if (sVar instanceof q) {
            q qVar = (q) sVar;
            this.m.invoke(new Integer(qVar.a), qVar.b);
        } else {
            if (!(sVar instanceof p)) {
                throw new NoWhenBranchMatchedException();
            }
            ((p) sVar).getClass();
            this.n.invoke("create_practice_test", com.quizlet.features.infra.models.upgrade.a.x);
        }
        return Unit.a;
    }
}
