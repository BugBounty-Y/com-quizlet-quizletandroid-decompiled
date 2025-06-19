package com.quizlet.upgrade.upsell.ui;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class c extends i implements Function2 {
    public int j;
    public final /* synthetic */ UpsellModalFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(UpsellModalFragment upsellModalFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = upsellModalFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            UpsellModalFragment upsellModalFragment = this.k;
            s0 s0Var = ((com.quizlet.upgrade.upsell.viewmodel.c) upsellModalFragment.J.getValue()).c;
            androidx.compose.runtime.internal.c cVar = new androidx.compose.runtime.internal.c(2, upsellModalFragment, UpsellModalFragment.class, "updateCtaButton", "updateCtaButton(Z)V", 4, 20);
            this.j = 1;
            if (e0.i(s0Var, cVar, this) == aVar) {
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
