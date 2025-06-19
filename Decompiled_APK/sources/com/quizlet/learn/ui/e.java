package com.quizlet.learn.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public final /* synthetic */ boolean j;
    public final /* synthetic */ InterfaceC0773a0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(boolean z, InterfaceC0773a0 interfaceC0773a0, h hVar) {
        super(2, hVar);
        this.j = z;
        this.k = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.k.setValue(Boolean.valueOf(this.j));
        return Unit.a;
    }
}
