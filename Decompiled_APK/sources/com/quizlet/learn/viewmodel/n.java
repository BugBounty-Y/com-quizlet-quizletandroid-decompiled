package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.X;
import com.quizlet.data.model.InterfaceC4176w0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ G k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new n(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        G g = this.k;
        if (i == 0) {
            Z.e(obj);
            com.quizlet.features.infra.basestudy.manager.f fVar = g.Z;
            com.quizlet.learn.logging.c[] cVarArr = com.quizlet.learn.logging.c.a;
            com.quizlet.learn.logging.b[] bVarArr = com.quizlet.learn.logging.b.a;
            com.quizlet.features.infra.basestudy.manager.f.j(fVar, "take_a_new_test", 4);
            long j = g.Z.u;
            this.j = 1;
            obj = g.u.o(j, this);
            if (obj == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        InterfaceC4176w0 interfaceC4176w0 = (InterfaceC4176w0) obj;
        X x = g.M;
        com.quizlet.features.infra.basestudy.manager.f fVar2 = g.Z;
        x.j(new com.quizlet.learn.data.F(fVar2.q, fVar2.l, fVar2.m, fVar2.k, g.f1, interfaceC4176w0));
        return Unit.a;
    }
}
