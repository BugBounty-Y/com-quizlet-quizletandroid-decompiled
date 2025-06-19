package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class w extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ x k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public w(x xVar, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = xVar;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        w wVar = new w(this.k, this.l, hVar);
        wVar.j = obj;
        return wVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((w) create((com.quizlet.search.data.newsearch.c) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.search.data.newsearch.c explanationsItem = (com.quizlet.search.data.newsearch.c) this.j;
        com.quizlet.quizletandroid.ui.common.images.capture.a aVar2 = this.k.k;
        aVar2.getClass();
        Intrinsics.checkNotNullParameter(explanationsItem, "explanationsItem");
        return com.quizlet.quizletandroid.ui.common.images.capture.a.j(aVar2, explanationsItem, null, this.l, 2);
    }
}
