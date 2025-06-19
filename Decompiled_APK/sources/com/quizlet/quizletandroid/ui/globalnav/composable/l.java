package com.quizlet.quizletandroid.ui.globalnav.composable;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.fragment.app.I;
import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.B;
import androidx.lifecycle.E;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.d0;

/* loaded from: classes3.dex */
public final class l extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ I j;
    public final /* synthetic */ d0 k;
    public final /* synthetic */ InterfaceC0773a0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public l(InterfaceC0773a0 interfaceC0773a0, I i, kotlin.coroutines.h hVar, d0 d0Var) {
        super(2, hVar);
        B b = B.a;
        this.j = i;
        this.k = d0Var;
        this.l = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        B b = B.a;
        return new l(this.l, this.j, hVar, this.k);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((l) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        I i = this.j;
        E eH = p0.h(i);
        InterfaceC0773a0 interfaceC0773a0 = this.l;
        d0 d0Var = this.k;
        B b = B.a;
        kotlinx.coroutines.E.A(eH, null, null, new k(interfaceC0773a0, i, null, d0Var), 3);
        return Unit.a;
    }
}
