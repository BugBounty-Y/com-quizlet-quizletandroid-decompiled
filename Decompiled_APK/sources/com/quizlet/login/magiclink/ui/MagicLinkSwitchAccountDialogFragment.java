package com.quizlet.login.magiclink.ui;

import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.compose.ui.platform.C0972v0;
import androidx.compose.ui.platform.ComposeView;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class MagicLinkSwitchAccountDialogFragment extends Hilt_MagicLinkSwitchAccountDialogFragment {
    public static final String x;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e v = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.login.magiclink.viewmodel.g.class), new p(this, 0), new p(this, 2), new p(this, 1));
    public final u w = kotlin.l.b(new e(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("MagicLinkSwitchAccountDialogFragment", "getSimpleName(...)");
        x = "MagicLinkSwitchAccountDialogFragment";
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final int I() {
        return R.style.InputBottomSheetDialog;
    }

    public final void R(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-465572999);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3178j5.c(null, false, null, androidx.compose.runtime.internal.e.e(1456038631, new l(this, 0), c0814p), c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(this, i, 5);
        }
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        com.quizlet.login.magiclink.viewmodel.g gVar = (com.quizlet.login.magiclink.viewmodel.g) this.v.getValue();
        String code = (String) this.w.getValue();
        gVar.getClass();
        Intrinsics.checkNotNullParameter(code, "code");
        gVar.g = code;
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        ComposeView composeView = new ComposeView(contextRequireContext, null, 6);
        composeView.setViewCompositionStrategy(C0972v0.b);
        composeView.setContent(new androidx.compose.runtime.internal.d(true, 164336257, new l(this, 1)));
        return composeView;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        super.onDismiss(dialog);
        ((com.quizlet.login.magiclink.viewmodel.g) this.v.getValue()).g = null;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        BottomSheetBehavior bottomSheetBehaviorG;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new o(this, null), 3);
        Dialog dialog = this.l;
        com.google.android.material.bottomsheet.h hVar = dialog instanceof com.google.android.material.bottomsheet.h ? (com.google.android.material.bottomsheet.h) dialog : null;
        if (hVar == null || (bottomSheetBehaviorG = hVar.g()) == null) {
            return;
        }
        bottomSheetBehaviorG.J(3);
        bottomSheetBehaviorG.J = true;
    }
}
