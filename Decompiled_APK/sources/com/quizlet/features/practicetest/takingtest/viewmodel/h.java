package com.quizlet.features.practicetest.takingtest.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.data.exceptions.practicetests.PracticeTestNoInternetException;
import com.quizlet.data.exceptions.practicetests.PracticeTestPaywallException;
import com.quizlet.data.exceptions.practicetests.PracticeTestUnsupportedException;
import com.quizlet.features.practicetest.takingtest.data.B;
import com.quizlet.features.practicetest.takingtest.data.G;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ Throwable k;
    public final /* synthetic */ l l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(Throwable th, l lVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = th;
        this.l = lVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        Object value2;
        Object value3;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            Throwable th = this.k;
            boolean z = th instanceof PracticeTestPaywallException;
            l lVar = this.l;
            if (z) {
                d0 d0Var = lVar.m;
                retrofit2.adapter.rxjava3.d dVar = com.quizlet.features.infra.models.upgrade.a.b;
                B b = new B("create_practice_test");
                this.j = 1;
                if (d0Var.emit(b, this) == aVar) {
                    return aVar;
                }
            } else if (th instanceof PracticeTestNoInternetException) {
                s0 s0Var = lVar.k;
                do {
                    value3 = s0Var.getValue();
                } while (!s0Var.k(value3, new G(new com.quizlet.features.practicetest.common.data.d(new g(lVar, 0)))));
            } else if (th instanceof PracticeTestUnsupportedException) {
                s0 s0Var2 = lVar.k;
                do {
                    value2 = s0Var2.getValue();
                } while (!s0Var2.k(value2, new G(new com.quizlet.features.practicetest.common.data.f(new g(lVar, 1)))));
            } else {
                s0 s0Var3 = lVar.k;
                do {
                    value = s0Var3.getValue();
                } while (!s0Var3.k(value, new G(new com.quizlet.features.practicetest.common.data.b(new g(lVar, 2)))));
                timber.log.c.a.p(th);
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
