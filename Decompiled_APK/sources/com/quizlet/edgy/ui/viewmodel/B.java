package com.quizlet.edgy.ui.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class B extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ M k;
    public final /* synthetic */ com.quizlet.edgy.ui.recyclerview.adapter.i l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(com.quizlet.edgy.ui.recyclerview.adapter.i iVar, M m, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = m;
        this.l = iVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new B(this.l, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        M m = this.k;
        if (i == 0) {
            Z.e(obj);
            s0 s0Var = m.p;
            do {
                value = s0Var.getValue();
            } while (!s0Var.k(value, n.a));
            long j = this.l.a;
            this.j = 1;
            if (m.d.b(j, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        m.k = null;
        m.o.clear();
        m.j.j("edgy_data_school_removed", "submit", "edgy_data", true);
        m.F(true);
        return Unit.a;
    }
}
