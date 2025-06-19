package com.quizlet.features.practicetest.takingtest;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.features.practicetest.takingtest.data.F;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class q extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ F j;
    public final /* synthetic */ InterfaceC0773a0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(F f, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = f;
        this.k = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new q(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((q) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.k.setValue(Boolean.valueOf(this.j.b()));
        return Unit.a;
    }
}
