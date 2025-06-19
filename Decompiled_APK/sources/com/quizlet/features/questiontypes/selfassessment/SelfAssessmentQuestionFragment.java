package com.quizlet.features.questiontypes.selfassessment;

import android.content.Context;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.compose.C1278k;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3205m5;
import com.quizlet.features.practicetest.results.i;
import com.quizlet.features.questiontypes.basequestion.k;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class SelfAssessmentQuestionFragment extends Hilt_SelfAssessmentQuestionFragment<androidx.viewbinding.a> {
    public static final String k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(k.class), new a(this, 0), new a(this, 2), new a(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("SelfAssessmentQuestionFragment", "getSimpleName(...)");
        k = "SelfAssessmentQuestionFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return k;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 12);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(796512915);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            Context contextRequireContext = requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
            AbstractC3178j5.b(null, false, null, androidx.compose.runtime.internal.e.e(-864506893, new i(3, AbstractC3205m5.e(contextRequireContext), this), c0814p), c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(this, i, 19);
        }
    }
}
