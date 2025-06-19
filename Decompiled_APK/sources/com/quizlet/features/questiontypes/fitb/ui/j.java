package com.quizlet.features.questiontypes.fitb.ui;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class j extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.features.questiontypes.fitb.g j;
    public final /* synthetic */ Function0 k;
    public final /* synthetic */ InterfaceC0773a0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public j(com.quizlet.features.questiontypes.fitb.g gVar, Function0 function0, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = gVar;
        this.k = function0;
        this.l = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new j(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((j) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.questiontypes.fitb.g gVar = this.j;
        this.l.setValue(Boolean.valueOf(gVar.d == com.quizlet.features.questiontypes.basequestion.data.a.b));
        if (gVar.d == com.quizlet.features.questiontypes.basequestion.data.a.c) {
            this.k.invoke();
        }
        return Unit.a;
    }
}
