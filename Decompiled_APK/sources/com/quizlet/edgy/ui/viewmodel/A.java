package com.quizlet.edgy.ui.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class A extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ M k;
    public final /* synthetic */ com.quizlet.edgy.ui.recyclerview.adapter.d l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public A(M m, com.quizlet.edgy.ui.recyclerview.adapter.d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = m;
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new A(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((A) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        M m = this.k;
        com.quizlet.edgy.ui.recyclerview.adapter.d dVar = this.l;
        if (i == 0) {
            Z.e(obj);
            do {
                s0Var = m.p;
                value = s0Var.getValue();
            } while (!s0Var.k(value, C4205f.a));
            long j = dVar.a;
            this.j = 1;
            if (m.e.e(j, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        m.o.remove(dVar);
        m.j.j("edgy_data_course_removed", "submit", "edgy_data", false);
        m.D();
        return Unit.a;
    }
}
