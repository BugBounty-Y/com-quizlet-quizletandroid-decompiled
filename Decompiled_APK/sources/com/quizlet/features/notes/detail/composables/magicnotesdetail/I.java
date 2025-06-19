package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.compose.runtime.InterfaceC0773a0;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class I extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.features.notes.detail.states.h j;
    public final /* synthetic */ InterfaceC0773a0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public I(com.quizlet.features.notes.detail.states.h hVar, InterfaceC0773a0 interfaceC0773a0, kotlin.coroutines.h hVar2) {
        super(2, hVar2);
        this.j = hVar;
        this.k = interfaceC0773a0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new I(this.j, this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((I) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.notes.data.c cVar = ((com.quizlet.features.notes.detail.states.g) this.j).c;
        this.k.setValue(Boolean.valueOf(cVar != null ? cVar.a : false));
        return Unit.a;
    }
}
