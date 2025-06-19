package com.quizlet.features.folders.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.folders.viewmodel.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4324e extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ N k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4324e(N n, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = n;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4324e c4324e = new C4324e(this.k, hVar);
        c4324e.j = obj;
        return c4324e;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4324e) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        kotlinx.coroutines.C c = (kotlinx.coroutines.C) this.j;
        N n = this.k;
        kotlinx.coroutines.E.A(c, null, null, new C4320a(n, null), 3);
        kotlinx.coroutines.E.A(c, null, null, new C4321b(n, null), 3);
        kotlinx.coroutines.E.A(c, null, null, new C4322c(n, null), 3);
        kotlinx.coroutines.E.A(c, null, null, new C4323d(n, null), 3);
        return Unit.a;
    }
}
