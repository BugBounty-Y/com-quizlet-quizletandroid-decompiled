package com.quizlet.features.notes.detail.composables.essay;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.coroutines.h;
import kotlin.coroutines.jvm.internal.i;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class d extends i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ Function0 k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(Function0 function0, h hVar) {
        super(2, hVar);
        this.k = function0;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final h create(Object obj, h hVar) {
        d dVar = new d(this.k, hVar);
        dVar.j = obj;
        return dVar;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((d) create((com.quizlet.features.notes.detail.events.a) obj, (h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        if (((com.quizlet.features.notes.detail.events.a) this.j) instanceof com.quizlet.features.notes.detail.events.a) {
            this.k.invoke();
        }
        return Unit.a;
    }
}
