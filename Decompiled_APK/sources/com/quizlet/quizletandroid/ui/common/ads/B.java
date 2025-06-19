package com.quizlet.quizletandroid.ui.common.ads;

import androidx.datastore.core.C1087t;
import androidx.glance.appwidget.protobuf.Z;
import androidx.paging.J0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.W;

/* loaded from: classes3.dex */
public final class B extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ E k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public B(E e, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = e;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        B b = new B(this.k, hVar);
        b.j = obj;
        return b;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((B) create((kotlin.v) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlin.v vVar = (kotlin.v) this.j;
        com.quizlet.ads.c cVar = (com.quizlet.ads.c) vVar.a;
        C4639f c4639f = (C4639f) vVar.b;
        C1087t c1087t = new C1087t(new J0(new com.quizlet.analytics.marketing.appsflyer.d(c4639f.b, 4), new p(cVar, (W) vVar.c, null), 5), 4);
        c4639f.c.i();
        return c1087t;
    }
}
