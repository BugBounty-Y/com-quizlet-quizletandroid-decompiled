package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x k;
    public final /* synthetic */ com.quizlet.assembly.compose.modals.x l;
    public final /* synthetic */ InterfaceC0773a0 m;
    public final /* synthetic */ InterfaceC0773a0 n;
    public final /* synthetic */ InterfaceC0773a0 o;
    public final /* synthetic */ InterfaceC0773a0 p;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public D(com.quizlet.assembly.compose.modals.x xVar, com.quizlet.assembly.compose.modals.x xVar2, InterfaceC0773a0 interfaceC0773a0, InterfaceC0773a0 interfaceC0773a02, InterfaceC0773a0 interfaceC0773a03, InterfaceC0773a0 interfaceC0773a04, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = xVar;
        this.l = xVar2;
        this.m = interfaceC0773a0;
        this.n = interfaceC0773a02;
        this.o = interfaceC0773a03;
        this.p = interfaceC0773a04;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        D d = new D(this.k, this.l, this.m, this.n, this.o, this.p, hVar);
        d.j = obj;
        return d;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((D) create((com.quizlet.features.notes.detail.menu.k) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.notes.detail.menu.k kVar = (com.quizlet.features.notes.detail.menu.k) this.j;
        if (kVar instanceof com.quizlet.features.notes.detail.menu.h) {
            this.m.setValue(Boolean.TRUE);
        } else if (kVar instanceof com.quizlet.features.notes.detail.menu.j) {
            com.quizlet.features.notes.detail.states.h hVar = (com.quizlet.features.notes.detail.states.h) this.n.getValue();
            Intrinsics.e(hVar, "null cannot be cast to non-null type com.quizlet.features.notes.detail.states.MagicNotesDetailUiState.Success");
            this.o.setValue(new com.quizlet.features.notes.data.e(((com.quizlet.features.notes.detail.states.g) hVar).a.i));
            com.quizlet.assembly.compose.modals.x.d(this.k);
        } else if (kVar instanceof com.quizlet.features.notes.detail.menu.i) {
            com.quizlet.assembly.compose.modals.x.d(this.l);
        } else if (kVar instanceof com.quizlet.features.notes.detail.menu.g) {
            this.p.setValue(Boolean.TRUE);
        }
        return Unit.a;
    }
}
