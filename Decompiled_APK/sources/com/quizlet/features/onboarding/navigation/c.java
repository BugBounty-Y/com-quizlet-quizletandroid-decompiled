package com.quizlet.features.onboarding.navigation;

import androidx.compose.foundation.text.input.internal.C0496b;
import androidx.glance.appwidget.protobuf.Z;
import kotlin.KotlinNothingValueException;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.Y;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ OnboardingNavigationActivity k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(OnboardingNavigationActivity onboardingNavigationActivity, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = onboardingNavigationActivity;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
        return kotlin.coroutines.intrinsics.a.a;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            int i2 = OnboardingNavigationActivity.j;
            OnboardingNavigationActivity onboardingNavigationActivity = this.k;
            Y y = ((p) onboardingNavigationActivity.e.getValue()).e;
            C0496b c0496b = new C0496b(onboardingNavigationActivity, 13);
            this.j = 1;
            if (y.a.b(c0496b, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        throw new KotlinNothingValueException();
    }
}
