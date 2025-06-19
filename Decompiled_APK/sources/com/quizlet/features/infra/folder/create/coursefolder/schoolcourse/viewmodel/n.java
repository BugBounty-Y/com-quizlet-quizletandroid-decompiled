package com.quizlet.features.infra.folder.create.coursefolder.schoolcourse.viewmodel;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.InterfaceC5002j;

/* loaded from: classes3.dex */
public final class n extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ o j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public n(o oVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = oVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new n(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((n) create((InterfaceC5002j) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        o oVar = this.j;
        oVar.getClass();
        E.A(p0.j(oVar), null, null, new g(oVar, null), 3);
        return Unit.a;
    }
}
