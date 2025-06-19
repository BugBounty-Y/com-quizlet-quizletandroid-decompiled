package com.quizlet.features.onboarding.ell;

import android.os.Bundle;
import androidx.glance.appwidget.protobuf.Z;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3206m6;
import kotlin.Pair;
import kotlin.Unit;
import kotlin.jvm.functions.Function2;

/* renamed from: com.quizlet.features.onboarding.ell.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4396a extends kotlin.coroutines.jvm.internal.i implements Function2 {
    public /* synthetic */ Object j;
    public final /* synthetic */ OnboardingELLBottomSheetFragment k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C4396a(OnboardingELLBottomSheetFragment onboardingELLBottomSheetFragment, kotlin.coroutines.h hVar) {
        super(2, hVar);
        this.k = onboardingELLBottomSheetFragment;
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final kotlin.coroutines.h create(Object obj, kotlin.coroutines.h hVar) {
        C4396a c4396a = new C4396a(this.k, hVar);
        c4396a.j = obj;
        return c4396a;
    }

    @Override // kotlin.jvm.functions.Function2
    public final Object invoke(Object obj, Object obj2) {
        return ((C4396a) create((u) obj, (kotlin.coroutines.h) obj2)).invokeSuspend(Unit.a);
    }

    @Override // kotlin.coroutines.jvm.internal.a
    public final Object invokeSuspend(Object obj) {
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        Z.e(obj);
        Bundle bundleA = AbstractC3206m6.a(new Pair("onboardingELLUpdateHomeResultKey", Boolean.valueOf(((u) this.j).a)));
        OnboardingELLBottomSheetFragment onboardingELLBottomSheetFragment = this.k;
        onboardingELLBottomSheetFragment.getParentFragmentManager().g0(bundleA, "onboardingELLRequestKey");
        onboardingELLBottomSheetFragment.G();
        return Unit.a;
    }
}
