package com.quizlet.features.achievements.ui.composables;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes2.dex */
public final class o extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.features.achievements.data.h j;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x k;
    public final /* synthetic */ InterfaceC0773a0 l;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public o(com.quizlet.features.achievements.data.h hVar, com.quizlet.assembly.compose.modals.x xVar, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.j = hVar;
        this.k = xVar;
        this.l = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new o(this.j, this.k, this.l, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((o) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.achievements.data.h hVar = this.j;
        com.quizlet.features.achievements.data.e eVar = hVar instanceof com.quizlet.features.achievements.data.e ? (com.quizlet.features.achievements.data.e) hVar : null;
        if ((eVar != null ? eVar.h : null) != null) {
            this.l.setValue(((com.quizlet.features.achievements.data.e) hVar).h);
            com.quizlet.assembly.compose.modals.x.d(this.k);
        }
        return Unit.a;
    }
}
