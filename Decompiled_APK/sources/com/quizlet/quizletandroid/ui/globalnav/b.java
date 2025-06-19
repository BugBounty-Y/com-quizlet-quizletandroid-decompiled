package com.quizlet.quizletandroid.ui.globalnav;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ GlobalNavigationActivity j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(GlobalNavigationActivity globalNavigationActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = globalNavigationActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((Unit) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        String str = GlobalNavigationActivity.u;
        this.j.P();
        return Unit.a;
    }
}
