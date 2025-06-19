package com.quizlet.features.folders.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.folders.composables.w, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4266w extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ androidx.lifecycle.J j;
    public final /* synthetic */ kotlinx.coroutines.flow.W k;
    public final /* synthetic */ InterfaceC0773a0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4266w(InterfaceC0773a0 interfaceC0773a0, androidx.lifecycle.J j, kotlin.coroutines.h hVar, kotlinx.coroutines.flow.W w) {
        super(2, hVar);
        androidx.lifecycle.B b = androidx.lifecycle.B.a;
        this.j = j;
        this.k = w;
        this.l = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        androidx.lifecycle.B b = androidx.lifecycle.B.a;
        return new C4266w(this.l, this.j, hVar, this.k);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4266w) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        androidx.lifecycle.J j = this.j;
        androidx.lifecycle.E eH = p0.h(j);
        InterfaceC0773a0 interfaceC0773a0 = this.l;
        androidx.lifecycle.B b = androidx.lifecycle.B.a;
        kotlinx.coroutines.E.A(eH, null, null, new C4265v(interfaceC0773a0, j, null, this.k), 3);
        return Unit.a;
    }
}
