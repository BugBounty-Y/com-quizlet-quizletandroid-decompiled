package com.quizlet.upgrade.ui.confirmation;

import android.view.LayoutInflater;
import android.view.ViewGroup;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.fragment.app.I;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3313z4;
import com.quizlet.assembly.compose.listitems.h;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.upgrade.data.UpgradePackage;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.l;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class UpgradeConfirmationFragment extends Hilt_UpgradeConfirmationFragment<androidx.viewbinding.a> {
    public static final String l;
    public final u j = l.b(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 12));
    public final e k = new e(K.a(c.class), new a(this, 0), new a(this, 2), new a(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("UpgradeConfirmationFragment", "getSimpleName(...)");
        l = "UpgradeConfirmationFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return l;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.search.b(this, 3);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1265427180);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            int i2 = ((UpgradePackage) this.j.getValue()).b;
            I iRequireActivity = requireActivity();
            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
            androidx.compose.material3.windowsizeclass.b bVarE = AbstractC3313z4.e(iRequireActivity, c0814p);
            AbstractC3178j5.b(bVarE, false, null, androidx.compose.runtime.internal.e.e(-343004084, new h(this, i2, bVarE, 8), c0814p), c0814p, 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(this, i, 19);
        }
    }
}
