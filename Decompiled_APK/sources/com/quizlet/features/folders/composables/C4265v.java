package com.quizlet.features.folders.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.flow.C4986c;
import kotlinx.coroutines.flow.e0;

/* renamed from: com.quizlet.features.folders.composables.v, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4265v extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ kotlinx.coroutines.flow.W k;
    public final /* synthetic */ androidx.lifecycle.J l;
    public final /* synthetic */ InterfaceC0773a0 m;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4265v(InterfaceC0773a0 interfaceC0773a0, androidx.lifecycle.J j, kotlin.coroutines.h hVar, kotlinx.coroutines.flow.W w) {
        super(2, hVar);
        androidx.lifecycle.B b = androidx.lifecycle.B.a;
        this.k = w;
        this.l = j;
        this.m = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        androidx.lifecycle.B b = androidx.lifecycle.B.a;
        return new C4265v(this.m, this.l, hVar, this.k);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4265v) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            androidx.glance.appwidget.protobuf.Z.e(obj);
            C4986c c4986cE = p0.e(this.k, this.l.getLifecycle(), androidx.lifecycle.B.c);
            Function2 function2 = (Function2) this.m.getValue();
            this.j = 1;
            if (e0.i(c4986cE, function2, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            androidx.glance.appwidget.protobuf.Z.e(obj);
        }
        return Unit.a;
    }
}
