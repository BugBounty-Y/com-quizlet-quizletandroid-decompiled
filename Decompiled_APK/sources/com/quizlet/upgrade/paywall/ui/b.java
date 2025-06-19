package com.quizlet.upgrade.paywall.ui;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.ui.learnpaywall.k;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;
import kotlinx.coroutines.flow.e0;

/* loaded from: classes3.dex */
public final class b extends i implements Function2 {
    public int j;
    public final /* synthetic */ PaywallFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(PaywallFragment paywallFragment, h hVar) {
        super(2, hVar);
        this.k = paywallFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            PaywallFragment paywallFragment = this.k;
            d0 d0Var = ((k) paywallFragment.R()).d;
            androidx.compose.runtime.internal.c cVar = new androidx.compose.runtime.internal.c(2, paywallFragment, PaywallFragment.class, "onNavigationEvent", "onNavigationEvent(Lcom/quizlet/upgrade/paywall/data/NavigationEvent;)V", 4, 19);
            this.j = 1;
            if (e0.i(d0Var, cVar, this) == aVar) {
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
