package com.quizlet.features.emailconfirmation.ui.activities;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class h extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ EmailConfirmationActivity j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public h(EmailConfirmationActivity emailConfirmationActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = emailConfirmationActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new h(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((h) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        com.quizlet.features.emailconfirmation.viewmodel.f fVar = (com.quizlet.features.emailconfirmation.viewmodel.f) ((com.quizlet.features.emailconfirmation.viewmodel.g) this.j.q.getValue());
        fVar.getClass();
        E.A(p0.j(fVar), null, null, new com.quizlet.features.emailconfirmation.viewmodel.e(fVar, null), 3);
        return Unit.a;
    }
}
