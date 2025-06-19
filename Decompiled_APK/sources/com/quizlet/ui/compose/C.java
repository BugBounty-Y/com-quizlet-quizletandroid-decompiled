package com.quizlet.ui.compose;

import androidx.compose.animation.core.C0238e;
import androidx.compose.runtime.InterfaceC0773a0;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class C extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ N j;
    public final /* synthetic */ kotlinx.coroutines.C k;
    public final /* synthetic */ C0238e l;
    public final /* synthetic */ float m;
    public final /* synthetic */ C0238e n;
    public final /* synthetic */ InterfaceC0773a0 o;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C(N n, kotlinx.coroutines.C c, C0238e c0238e, float f, C0238e c0238e2, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = n;
        this.k = c;
        this.l = c0238e;
        this.m = f;
        this.n = c0238e2;
        this.o = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        InterfaceC0773a0 interfaceC0773a0 = this.o;
        return new C(this.j, this.k, this.l, this.m, this.n, interfaceC0773a0, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        androidx.glance.appwidget.protobuf.Z.e(obj);
        M m = M.a;
        N n = this.j;
        if (Intrinsics.b(n, m)) {
            InterfaceC0773a0 interfaceC0773a0 = this.o;
            kotlinx.coroutines.E.A(this.k, null, null, new B(this.l, this.m, this.n, interfaceC0773a0, null), 3);
        } else if (!Intrinsics.b(n, L.a)) {
            throw new NoWhenBranchMatchedException();
        }
        return Unit.a;
    }
}
