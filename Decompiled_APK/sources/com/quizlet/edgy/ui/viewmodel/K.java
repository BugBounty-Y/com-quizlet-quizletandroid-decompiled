package com.quizlet.edgy.ui.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.U1;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes2.dex */
public final class K extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ com.quizlet.edgy.ui.recyclerview.adapter.i k;
    public final /* synthetic */ M l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public K(com.quizlet.edgy.ui.recyclerview.adapter.i iVar, M m, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = iVar;
        this.l = m;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new K(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((K) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        s0 s0Var;
        Object value;
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        com.quizlet.edgy.ui.recyclerview.adapter.i iVar = this.k;
        M m = this.l;
        if (i == 0) {
            Z.e(obj);
            if (Intrinsics.b(iVar, m.k)) {
                return Unit.a;
            }
            do {
                s0Var = m.p;
                value = s0Var.getValue();
            } while (!s0Var.k(value, n.a));
            m.j.j("edgy_data_school_submitted", "submit", "edgy_data", true);
            long j = iVar.a;
            U1 u1 = U1.MAIN;
            this.j = 1;
            if (m.f.m(j, u1, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        m.j.j("edgy_data_school_screen_added_new_school", "submit", "edgy_data", true);
        m.E(iVar, true);
        return Unit.a;
    }
}
