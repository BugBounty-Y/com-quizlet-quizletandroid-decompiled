package com.quizlet.features.onboarding.ell;

import androidx.glance.appwidget.protobuf.Z;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C;
import kotlinx.coroutines.flow.Y;
import kotlinx.coroutines.flow.e0;

/* renamed from: com.quizlet.features.onboarding.ell.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4397b extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public int j;
    public final /* synthetic */ OnboardingELLBottomSheetFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4397b(OnboardingELLBottomSheetFragment onboardingELLBottomSheetFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = onboardingELLBottomSheetFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        return new C4397b(this.k, hVar);
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4397b) create((C) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        int i = this.j;
        if (i == 0) {
            Z.e(obj);
            String str = OnboardingELLBottomSheetFragment.w;
            OnboardingELLBottomSheetFragment onboardingELLBottomSheetFragment = this.k;
            Y y = new Y(((B) onboardingELLBottomSheetFragment.v.getValue()).d);
            C4396a c4396a = new C4396a(onboardingELLBottomSheetFragment, null);
            this.j = 1;
            if (e0.i(y, c4396a, this) == aVar) {
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
