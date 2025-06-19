package com.quizlet.features.settings.composables.deleteaccount;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ InterfaceC0773a0 j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        Boolean bool = (Boolean) obj;
        bool.booleanValue();
        return ((h) create(bool, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.j.setValue(Boolean.TRUE);
        return Unit.a;
    }
}
