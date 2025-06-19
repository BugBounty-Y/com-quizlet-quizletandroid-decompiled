package com.quizlet.features.setpage;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ r k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(r rVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = rVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) throws Throwable {
        ((o) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) throws Throwable {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            throw new KotlinNothingValueException();
        }
        Z.e(obj);
        r rVar = this.k;
        d0 d0Var = ((com.quizlet.features.setpage.termlist.viewmodel.j) rVar.L.getValue()).i;
        m mVar = new m(rVar, 1);
        this.j = 1;
        d0Var.getClass();
        d0.m(d0Var, mVar, this);
        return aVar;
    }
}
