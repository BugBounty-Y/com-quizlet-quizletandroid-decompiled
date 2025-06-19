package com.quizlet.quizletandroid.ui.deeplinkinterstitial;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.B;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class d extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ DeepLinkInterstitialActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(DeepLinkInterstitialActivity deepLinkInterstitialActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = deepLinkInterstitialActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new d(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            B b = B.c;
            DeepLinkInterstitialActivity deepLinkInterstitialActivity = this.k;
            c cVar = new c(deepLinkInterstitialActivity, null);
            this.j = 1;
            if (p0.m(deepLinkInterstitialActivity, b, cVar, this) == aVar) {
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
