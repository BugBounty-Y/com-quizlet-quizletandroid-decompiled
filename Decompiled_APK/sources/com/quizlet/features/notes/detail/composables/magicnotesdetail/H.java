package com.quizlet.features.notes.detail.composables.magicnotesdetail;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* loaded from: classes3.dex */
public final class H extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ com.quizlet.features.notes.detail.viewmodels.v j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public H(com.quizlet.features.notes.detail.viewmodels.v vVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = vVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new H(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((H) create((kotlinx.coroutines.C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        this.j.F(com.quizlet.features.notes.common.events.x.a);
        return Unit.a;
    }
}
