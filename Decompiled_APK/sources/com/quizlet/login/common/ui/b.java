package com.quizlet.login.common.ui;

import androidx.compose.material3.C0585a1;
import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ C0585a1 j;
    public final /* synthetic */ Function1 k;
    public final /* synthetic */ InterfaceC0773a0 l;
    public final /* synthetic */ InterfaceC0773a0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(C0585a1 c0585a1, Function1 function1, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = c0585a1;
        this.k = function1;
        this.l = interfaceC0773a0;
        this.m = interfaceC0773a02;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new b(this.j, this.k, this.l, this.m, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        Long lB = this.j.b();
        if (lB != null) {
            InterfaceC0773a0 interfaceC0773a0 = this.l;
            if (!lB.equals((Long) interfaceC0773a0.getValue())) {
                InterfaceC0773a0 interfaceC0773a02 = this.m;
                if (((Boolean) interfaceC0773a02.getValue()).booleanValue()) {
                    interfaceC0773a02.setValue(Boolean.FALSE);
                }
                interfaceC0773a0.setValue(lB);
                this.k.invoke(lB);
            }
        }
        return Unit.a;
    }
}
