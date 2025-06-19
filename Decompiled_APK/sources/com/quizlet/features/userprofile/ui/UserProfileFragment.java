package com.quizlet.features.userprofile.ui;

import android.view.LayoutInflater;
import android.view.ViewGroup;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.fragment.app.I;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3313z4;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class UserProfileFragment extends Hilt_UserProfileFragment<androidx.viewbinding.a> {
    public static final String k;
    public com.quizlet.features.userprofile.navigation.b j;

    static {
        Intrinsics.checkNotNullExpressionValue("UserProfileFragment", "getSimpleName(...)");
        k = "UserProfileFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return k;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 18);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-1278431836);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            I iRequireActivity = requireActivity();
            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
            androidx.compose.material3.windowsizeclass.b bVarE = AbstractC3313z4.e(iRequireActivity, c0814p);
            AbstractC3178j5.b(bVarE, false, null, androidx.compose.runtime.internal.e.e(1533851396, new com.quizlet.features.practicetest.results.i(16, bVarE, this), c0814p), c0814p, 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(this, i, 1);
        }
    }
}
