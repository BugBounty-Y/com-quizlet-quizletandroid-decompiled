package com.quizlet.upgrade.upsell.ui;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class f extends i implements Function2 {
    public int j;
    public final /* synthetic */ UpsellModalFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public f(UpsellModalFragment upsellModalFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = upsellModalFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new f(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((f) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            UpsellModalFragment upsellModalFragment = this.k;
            d0 d0Var = ((com.quizlet.upgrade.upsell.viewmodel.c) upsellModalFragment.J.getValue()).d;
            e eVar = new e(upsellModalFragment, null);
            this.j = 1;
            if (e0.i(d0Var, eVar, this) == aVar) {
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
