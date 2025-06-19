package com.quizlet.features.setpage.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.generated.enums.A1;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;

/* loaded from: classes3.dex */
public final class E extends kotlin.coroutines.jvm.internal.i implements Function1 {
    public int j;
    public final /* synthetic */ P k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public E(P p, kotlin.coroutines.h hVar) {
        super(1, hVar);
        this.k = p;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(kotlin.coroutines.h hVar) {
        return new E(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function1
    public final Object invoke(Object obj) {
        return ((E) create((kotlin.coroutines.h) obj)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i != 0) {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
            return obj;
        }
        Z.e(obj);
        P p = this.k;
        com.quizlet.features.setpage.studymodes.viewmodel.a aVar2 = p.F;
        long jD = p.D();
        this.j = 1;
        com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s sVar = (com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.s) aVar2;
        sVar.getClass();
        Object objD = sVar.d(jD, A1.MOBILE_SCATTER, new com.quizlet.quizletandroid.ui.setpage.studymodes.viewmodel.l(sVar, jD, null), this);
        return objD == aVar ? aVar : objD;
    }
}
