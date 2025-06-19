package com.quizlet.features.onboarding.ell;

import androidx.glance.appwidget.protobuf.Z;
import com.quizlet.eventlogger.model.OnboardingELLEventLog;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class y extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public final /* synthetic */ B j;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public y(B b, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.j = b;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new y(this.j, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((y) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        n nVar = this.j.c;
        nVar.getClass();
        nVar.a(OnboardingELLEventLog.Companion.a(OnboardingELLEventLog.b, "onboarding_ell_screen_view"));
        return Unit.a;
    }
}
