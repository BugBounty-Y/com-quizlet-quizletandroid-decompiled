package com.quizlet.features.questiontypes.mcq;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ l k;
    public final /* synthetic */ com.quizlet.features.questiontypes.mcq.data.d l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(l lVar, com.quizlet.features.questiontypes.mcq.data.d dVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = lVar;
        this.l = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new e(this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            s0 s0Var = this.k.s;
            com.quizlet.features.questiontypes.basequestion.data.a aVar2 = this.l.d;
            this.j = 1;
            s0Var.l(aVar2);
            if (Unit.a == aVar) {
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
