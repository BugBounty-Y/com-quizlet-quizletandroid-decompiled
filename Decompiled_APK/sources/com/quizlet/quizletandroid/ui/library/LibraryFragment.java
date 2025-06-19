package com.quizlet.quizletandroid.ui.library;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3313z4;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class LibraryFragment extends Hilt_LibraryFragment<androidx.viewbinding.a> {
    public static final String n;
    public com.quizlet.offline.managers.b j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l;
    public com.quizlet.explanations.navigation.b m;

    static {
        Intrinsics.checkNotNullExpressionValue("LibraryFragment", "getSimpleName(...)");
        n = "LibraryFragment";
    }

    public LibraryFragment() {
        C4669n c4669n = new C4669n(this, 0);
        kotlin.m mVar = kotlin.m.c;
        kotlin.k kVarA = kotlin.l.a(mVar, new com.quizlet.login.recovery.forgotpassword.ui.e(c4669n, 8));
        this.k = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(c0.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 7), new C4668m(this, kVarA, 1), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 8));
        kotlin.k kVarA2 = kotlin.l.a(mVar, new com.quizlet.login.recovery.forgotpassword.ui.e(new C4669n(this, 1), 9));
        this.l = new com.quizlet.data.repository.folderwithcreatorinclass.e(kotlin.jvm.internal.K.a(com.quizlet.explanations.myexplanations.viewmodel.m.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA2, 9), new C4668m(this, kVarA2, 0), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA2, 10));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return n;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 19);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(-2113859115);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            androidx.fragment.app.I iRequireActivity = requireActivity();
            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
            AbstractC3178j5.b(AbstractC3313z4.e(iRequireActivity, c0814p), false, null, androidx.compose.runtime.internal.e.e(1060873013, new C4665j(this, 0), c0814p), c0814p, 3072, 6);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(this, i, 8);
        }
    }

    public final com.quizlet.explanations.navigation.b U() {
        com.quizlet.explanations.navigation.b bVar = this.m;
        if (bVar != null) {
            return bVar;
        }
        Intrinsics.m("navigationManager");
        throw null;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        androidx.lifecycle.J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        kotlinx.coroutines.E.A(p0.h(viewLifecycleOwner), null, null, new C4667l(this, null), 3);
        ((com.quizlet.explanations.myexplanations.viewmodel.m) ((com.quizlet.explanations.myexplanations.viewmodel.a) this.l.getValue())).q.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.fragments.c(new com.quizlet.quizletandroid.ui.common.ads.G(this, 10), 0));
    }
}
