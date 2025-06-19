package com.quizlet.features.notes.upload.composables.upload;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import com.quizlet.features.notes.upload.viewmodels.k;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes3.dex */
public final class i extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ k j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public i(k kVar, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = kVar;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new i(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((i) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        k kVar = this.j;
        E.A(p0.j(kVar), null, null, new com.quizlet.features.notes.upload.viewmodels.f(kVar, null), 3);
        return Unit.a;
    }
}
