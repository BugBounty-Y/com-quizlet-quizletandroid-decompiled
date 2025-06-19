package com.quizlet.features.onboarding.ell;

import android.app.Dialog;
import android.os.Bundle;
import android.view.View;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;
import kotlinx.coroutines.flow.Z;

@Metadata
/* loaded from: classes3.dex */
public final class OnboardingELLBottomSheetFragment extends Hilt_OnboardingELLBottomSheetFragment {
    public static final String w;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e v = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(B.class), new d(this, 0), new d(this, 2), new d(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("OnboardingELLBottomSheetFragment", "getSimpleName(...)");
        w = "OnboardingELLBottomSheetFragment";
    }

    @Override // com.quizlet.baseui.base.BaseComposeBottomSheetFragment
    public final void S(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(-1386160657);
        AbstractC3178j5.b(null, false, null, androidx.compose.runtime.internal.e.e(-379193201, new androidx.navigation.compose.o(26, this, C0776c.m(new Z(((B) this.v.getValue()).e), c0814p)), c0814p), c0814p, 3072, 7);
        c0814p.p(false);
    }

    @Override // com.quizlet.baseui.base.BaseComposeBottomSheetFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new c(this, null), 3);
        Dialog dialog = this.l;
        com.google.android.material.bottomsheet.h hVar = dialog instanceof com.google.android.material.bottomsheet.h ? (com.google.android.material.bottomsheet.h) dialog : null;
        BottomSheetBehavior bottomSheetBehaviorG = hVar != null ? hVar.g() : null;
        if (bottomSheetBehaviorG != null) {
            bottomSheetBehaviorG.J(3);
        }
        if (bottomSheetBehaviorG != null) {
            bottomSheetBehaviorG.J = true;
        }
        if (hVar != null) {
            hVar.setOnCancelListener(new com.facebook.internal.K(this, 3));
        }
    }
}
