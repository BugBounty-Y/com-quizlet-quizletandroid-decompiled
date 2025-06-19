package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ D k;
    public final /* synthetic */ boolean l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(D d, boolean z, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = d;
        this.l = z;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C c = new C(this.k, this.l, hVar);
        c.j = obj;
        return c;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((com.quizlet.search.data.newsearch.c) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
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
