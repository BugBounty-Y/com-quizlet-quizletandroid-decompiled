package com.quizlet.learn.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.studiablemodels.StudiableRoundProgress;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class F extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ G j;
    public final /* synthetic */ com.google.firebase.crashlytics.internal.common.i k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(G g, com.google.firebase.crashlytics.internal.common.i iVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = g;
        this.k = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new F(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((F) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        Object value2;
        int i;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        G g = this.j;
        StudiableTaskProgress studiableTaskProgressB = g.f.b();
        StudiableRoundProgress studiableRoundProgressK = g.K();
        s0 s0Var = g.J;
        com.google.firebase.crashlytics.internal.common.i iVar = this.k;
        if (studiableTaskProgressB == null || studiableRoundProgressK == null) {
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, new com.quizlet.learn.ui.toolbar.g(new com.quizlet.learn.ui.toolbar.a(studiableRoundProgressK), iVar)));
        } else {
            int i2 = studiableTaskProgressB.a;
            com.quizlet.learn.ui.toolbar.d cVar = (i2 == 0 || (i = studiableTaskProgressB.b) == 0 || i2 != i) ? new com.quizlet.learn.ui.toolbar.c(new com.quizlet.learn.ui.progress.g(i2, g.s1, studiableTaskProgressB.b, com.quizlet.learn.ui.progress.i.c, 48)) : com.quizlet.learn.ui.toolbar.b.a;
            do {
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, new com.quizlet.learn.ui.toolbar.g(cVar, iVar)));
        }
        return Unit.a;
    }
}
