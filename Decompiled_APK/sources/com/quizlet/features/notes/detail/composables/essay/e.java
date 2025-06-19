package com.quizlet.features.notes.detail.composables.essay;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class e extends i implements Function2 {
    public final /* synthetic */ com.quizlet.features.notes.detail.viewmodels.d j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(com.quizlet.features.notes.detail.viewmodels.d dVar, h hVar) {
        super(2, hVar);
        this.j = dVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        return new e(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((e) create((C) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.notes.detail.viewmodels.c cVar = (com.quizlet.features.notes.detail.viewmodels.c) this.j;
        E.A(p0.j(cVar), null, null, new com.quizlet.features.notes.detail.viewmodels.a(cVar, null), 3);
        return Unit.a;
    }
}
