package com.quizlet.login.magiclink.ui;

import android.content.Context;
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
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class MagicLinkLogOutDialogFragment extends Hilt_MagicLinkLogOutDialogFragment {
    public static final String x;
    public final u v = kotlin.l.b(new e(this, 0));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e w = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.login.magiclink.viewmodel.g.class), new j(this, 0), new j(this, 2), new j(this, 1));

    static {
        Intrinsics.checkNotNullExpressionValue("MagicLinkLogOutDialogFragment", "getSimpleName(...)");
        x = "MagicLinkLogOutDialogFragment";
    }

    public final void Q(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(844587541);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3178j5.c(null, false, null, androidx.compose.runtime.internal.e.e(-2009968125, new f(this, 0), c0814p), c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(this, i, 4);
        }
    }

    @Override // androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        ComposeView composeView = new ComposeView(contextRequireContext, null, 6);
        composeView.setViewCompositionStrategy(C0972v0.b);
        composeView.setContent(new androidx.compose.runtime.internal.d(true, 1091598109, new f(this, 1)));
        return composeView;
    }

    @Override // androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new i(this, null), 3);
    }
}
