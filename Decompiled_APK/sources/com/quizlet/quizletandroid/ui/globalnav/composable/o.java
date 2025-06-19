package com.quizlet.quizletandroid.ui.globalnav.composable;

import androidx.fragment.app.I;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.quizletandroid.ui.startpage.nav2.viewmodels.L;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.quizletandroid.ui.globalnav.navigation.a j;
    public final /* synthetic */ I k;
    public final /* synthetic */ L l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(com.quizlet.quizletandroid.ui.globalnav.navigation.a aVar, I i, L l, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = aVar;
        this.k = i;
        this.l = l;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.learn.ads.g gVar = new com.quizlet.learn.ads.g(0, this.l, L.class, "onResumeFromOneTrustConsent", "onResumeFromOneTrustConsent()V", 0, 29);
        n nVar = new n(0, this.l, L.class, "onResumeFromOneTrustConsent", "onResumeFromOneTrustConsent()V", 0, 0);
        this.j.d(this.k, gVar, nVar);
        return Unit.a;
    }
}
