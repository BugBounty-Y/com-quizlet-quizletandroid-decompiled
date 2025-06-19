package com.quizlet.features.setpage.header.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import androidx.navigation.compose.C1278k;
import com.facebook.appevents.iap.u;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.quizlet.eventlogger.features.setpage.SetPagePerformanceLogger;
import com.quizlet.features.infra.snackbar.n;
import com.quizlet.features.practicetest.results.i;
import com.quizlet.features.setpage.viewmodel.P;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes3.dex */
public final class SetPageHeaderFragment extends Hilt_SetPageHeaderFragment<androidx.viewbinding.a> implements n {
    public static final String m;
    public SetPagePerformanceLogger j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(P.class), new e(this, 0), new e(this, 2), new e(this, 1));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.setpage.header.viewmodel.f.class), new e(this, 3), new e(this, 5), new e(this, 4));

    static {
        Intrinsics.checkNotNullExpressionValue("SetPageHeaderFragment", "getSimpleName(...)");
        m = "SetPageHeaderFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return m;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 15);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(71611502);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3178j5.b(null, false, null, androidx.compose.runtime.internal.e.e(1739153166, new i(7, this, C0776c.m(((com.quizlet.features.setpage.header.viewmodel.f) U()).g, c0814p)), c0814p), c0814p, 3072, 7);
            SetPagePerformanceLogger setPagePerformanceLogger = this.j;
            if (setPagePerformanceLogger == null) {
                Intrinsics.m("setPagePerformanceLogger");
                throw null;
            }
            setPagePerformanceLogger.e();
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(this, i, 27);
        }
    }

    public final com.quizlet.features.setpage.header.viewmodel.a U() {
        return (com.quizlet.features.setpage.header.viewmodel.a) this.l.getValue();
    }

    public final P V() {
        return (P) this.k.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        com.quizlet.features.setpage.header.viewmodel.f fVar = (com.quizlet.features.setpage.header.viewmodel.f) U();
        y0 y0Var = fVar.j;
        if (y0Var != null) {
            y0Var.j(null);
        }
        fVar.j = E.A(p0.j(fVar), u.d(), null, new com.quizlet.features.setpage.header.viewmodel.d(fVar, null), 2);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStop() {
        super.onStop();
        com.quizlet.features.setpage.header.viewmodel.f fVar = (com.quizlet.features.setpage.header.viewmodel.f) U();
        y0 y0Var = fVar.j;
        if (y0Var != null) {
            y0Var.j(null);
        }
        fVar.j = null;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        b bVar = new b(((com.quizlet.features.setpage.header.viewmodel.f) U()).h, new d(this, null), null);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new c(this, bVar, null), 3);
    }
}
