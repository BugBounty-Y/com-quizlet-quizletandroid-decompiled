package com.quizlet.quizletandroid.ui.deeplinkinterstitial;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.e0;
import kotlinx.coroutines.flow.s0;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ DeepLinkInterstitialActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(DeepLinkInterstitialActivity deepLinkInterstitialActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = deepLinkInterstitialActivity;
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
            String str = DeepLinkInterstitialActivity.s;
            DeepLinkInterstitialActivity deepLinkInterstitialActivity = this.k;
            s0 s0Var = ((i) deepLinkInterstitialActivity.r.getValue()).g;
            b bVar = new b(deepLinkInterstitialActivity, null);
            this.j = 1;
            if (e0.i(s0Var, bVar, this) == aVar) {
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
