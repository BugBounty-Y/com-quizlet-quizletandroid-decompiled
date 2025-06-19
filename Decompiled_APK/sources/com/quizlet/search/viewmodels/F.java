package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class F extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ G k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public F(G g, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = g;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        F f = new F(this.k, hVar);
        f.j = obj;
        return f;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((F) create((com.quizlet.search.data.newsearch.e) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.search.data.newsearch.e userItem = (com.quizlet.search.data.newsearch.e) this.j;
        com.quizlet.quizletandroid.ui.common.images.capture.a aVar2 = this.k.j;
        aVar2.getClass();
        Intrinsics.checkNotNullParameter(userItem, "userItem");
        return com.quizlet.quizletandroid.ui.common.images.capture.a.j(aVar2, userItem, null, false, 6);
    }
}
