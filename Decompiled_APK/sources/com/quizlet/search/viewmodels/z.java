package com.quizlet.search.viewmodels;

import androidx.glance.appwidget.protobuf.Z;
import java.util.LinkedHashSet;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class z extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ A k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public z(A a, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        z zVar = new z(this.k, hVar);
        zVar.j = obj;
        return zVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((z) create((com.quizlet.search.data.newsearch.d) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.search.data.newsearch.d setItem = (com.quizlet.search.data.newsearch.d) this.j;
        A a = this.k;
        com.quizlet.quizletandroid.ui.common.images.capture.a aVar2 = a.j;
        LinkedHashSet studySetsIds = a.m;
        aVar2.getClass();
        Intrinsics.checkNotNullParameter(setItem, "setItem");
        Intrinsics.checkNotNullParameter(studySetsIds, "studySetsIds");
        return com.quizlet.quizletandroid.ui.common.images.capture.a.j(aVar2, setItem, studySetsIds, false, 4);
    }
}
