package com.quizlet.features.onboarding.ell;

import androidx.glance.appwidget.protobuf.Z;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C;

/* loaded from: classes3.dex */
public final class c extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ OnboardingELLBottomSheetFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(OnboardingELLBottomSheetFragment onboardingELLBottomSheetFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = onboardingELLBottomSheetFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new c(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((c) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            OnboardingELLBottomSheetFragment onboardingELLBottomSheetFragment = this.k;
            J viewLifecycleOwner = onboardingELLBottomSheetFragment.getViewLifecycleOwner();
            Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
            androidx.lifecycle.B b = androidx.lifecycle.B.c;
            C4397b c4397b = new C4397b(onboardingELLBottomSheetFragment, null);
            this.j = 1;
            if (p0.m(viewLifecycleOwner, b, c4397b, this) == aVar) {
                return aVar;
            }
        } else {
            if (i != 1) {
                throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
            }
            Z.e(obj);
        }
        return Unit.a;
    }
}
