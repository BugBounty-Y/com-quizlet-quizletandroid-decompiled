package com.quizlet.features.practicetest.results.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.practicetests.PracticeTestNoInternetException;
import com.quizlet.data.exceptions.practicetests.PracticeTestPaywallException;
import com.quizlet.features.practicetest.results.data.p;
import com.quizlet.features.practicetest.results.data.u;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class f extends i implements Function2 {
    public final /* synthetic */ Throwable j;
    public final /* synthetic */ h k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(Throwable th, h hVar, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.j = th;
        this.k = hVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        Object value2;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        Throwable th = this.j;
        boolean z = th instanceof PracticeTestPaywallException;
        h hVar = this.k;
        if (z) {
            d0 d0Var = hVar.l;
            com.quizlet.features.infra.models.upgrade.a navigationSource = com.quizlet.features.infra.models.upgrade.a.x;
            Intrinsics.checkNotNullParameter("create_practice_test", "upgradeSource");
            Intrinsics.checkNotNullParameter(navigationSource, "navigationSource");
            d0Var.h(new p());
        } else if (th instanceof PracticeTestNoInternetException) {
            s0 s0Var = hVar.m;
            do {
                value2 = s0Var.getValue();
            } while (!s0Var.k(value2, new u(new com.quizlet.features.practicetest.common.data.d(new e(hVar, 0)))));
        } else {
            s0 s0Var2 = hVar.m;
            do {
                value = s0Var2.getValue();
            } while (!s0Var2.k(value, new u(new com.quizlet.features.practicetest.common.data.b(new e(hVar, 1)))));
            timber.log.c.a.p(th);
        }
        return Unit.a;
    }
}
