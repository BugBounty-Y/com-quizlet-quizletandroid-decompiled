package com.quizlet.search;

import android.content.DialogInterface;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.fragment.app.AbstractC1136h0;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.t;
import com.quizlet.search.data.term.TermSearchUiModel;
import com.quizlet.search.viewmodels.M;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.m;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class TermSearchFragment extends Hilt_TermSearchFragment {
    public static final String V;
    public com.quizlet.quizletandroid.ui.navigationmanagers.g J;
    public final boolean K = true;
    public b L;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e M;

    static {
        String name = TermSearchFragment.class.getName();
        Intrinsics.checkNotNullExpressionValue(name, "getName(...)");
        V = name;
    }

    public TermSearchFragment() {
        kotlin.k kVarA = kotlin.l.a(m.c, new t(new t(this, 7), 8));
        this.M = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(M.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 15), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 29), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 16));
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        b bVar = this.L;
        if (bVar == null) {
            throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
        }
        container.addView(bVar.getRoot());
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment
    public final boolean W() {
        return this.K;
    }

    public final void f0(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(350594765);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3178j5.b(null, false, null, androidx.compose.runtime.internal.e.e(-117810835, new h(this, 0), c0814p), c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(this, i, 17);
        }
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        this.L = new b(this, 1);
        return super.onCreateView(inflater, viewGroup, bundle);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        super.onDismiss(dialog);
        M m = (M) this.M.getValue();
        if (m.i) {
            TermSearchUiModel termSearchUiModel = m.e;
            m.d.b(termSearchUiModel.a, termSearchUiModel.b);
            m.i = false;
        }
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.UnstyledConvertibleModalDialogFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new k(this, null), 3);
    }
}
