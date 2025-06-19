package com.quizlet.quizletandroid.ui.studymodes.testmode.start;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.quizlet.features.infra.basestudy.data.models.logging.StudyEventLogData;
import com.quizlet.generated.enums.G1;
import com.quizlet.quizletandroid.ui.studymodes.testmode.viewmodels.G;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class TestModeStartFragment extends Hilt_TestModeStartFragment<androidx.viewbinding.a> {
    public static final String l;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k;

    static {
        Intrinsics.checkNotNullExpressionValue("TestModeStartFragment", "getSimpleName(...)");
        l = "TestModeStartFragment";
    }

    public TestModeStartFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.quizletandroid.ui.studymodes.match.fragment.t(new n(this, 3), 2));
        this.j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(A.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 9), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 26), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 10));
        this.k = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(G.class), new n(this, 0), new n(this, 2), new n(this, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return l;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 29);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(228628682);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3178j5.b(null, false, null, androidx.compose.runtime.internal.e.e(437420586, new k(this, 0), c0814p), c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new com.quizlet.features.settings.composables.dialogs.a(this, i, 13);
        }
    }

    public final A U() {
        return (A) this.j.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        A aU = U();
        StudyEventLogData studyEventLogDataC = aU.C();
        G1 g1 = G1.SET;
        Long lValueOf = Long.valueOf(studyEventLogDataC.b);
        Long lValueOf2 = Long.valueOf(studyEventLogDataC.c);
        Boolean boolValueOf = Boolean.valueOf(studyEventLogDataC.d);
        aU.c.e(studyEventLogDataC.a, g1, 1, null, lValueOf, lValueOf2, boolValueOf, "settings", null);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStop() {
        super.onStop();
        A aU = U();
        StudyEventLogData studyEventLogDataC = aU.C();
        G1 g1 = G1.SET;
        Long lValueOf = Long.valueOf(studyEventLogDataC.b);
        Long lValueOf2 = Long.valueOf(studyEventLogDataC.c);
        Boolean boolValueOf = Boolean.valueOf(studyEventLogDataC.d);
        aU.c.f(studyEventLogDataC.a, g1, 1, null, lValueOf, lValueOf2, boolValueOf, "settings");
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((G) this.k.getValue()).y.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.fragments.c(new com.quizlet.quizletandroid.ui.common.ads.G(this, 23), (byte) 0, false));
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new m(this, null), 3);
    }
}
