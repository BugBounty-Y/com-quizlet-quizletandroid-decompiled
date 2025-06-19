package com.quizlet.features.setpage.terms.ui;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.credentials.playservices.controllers.BeginSignIn.d;
import androidx.lifecycle.J;
import androidx.lifecycle.p0;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.widgets.QSegmentedControl;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class SelectedTermsModeFragment extends Hilt_SelectedTermsModeFragment<com.quizlet.features.setpage.databinding.b> {
    public static final String l;
    public final e j;
    public final com.google.firebase.crashlytics.internal.settings.b k;

    static {
        Intrinsics.checkNotNullExpressionValue("SelectedTermsModeFragment", "getSimpleName(...)");
        l = "SelectedTermsModeFragment";
    }

    public SelectedTermsModeFragment() {
        com.quizlet.featuregate.growthbook.a aVar = new com.quizlet.featuregate.growthbook.a(this, 15);
        k kVarA = l.a(m.c, new assistantMode.experiments.a(new assistantMode.experiments.a(this, 27), 28));
        this.j = new e(K.a(com.quizlet.features.setpage.viewmodel.selectedtermsmode.b.class), new C4062f(kVarA, 29), new d(27, this, kVarA), new d(26, aVar, kVarA));
        this.k = new com.google.firebase.crashlytics.internal.settings.b(this, 22);
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return l;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_selected_terms_mode, viewGroup, false);
        QSegmentedControl qSegmentedControl = (QSegmentedControl) AbstractC3375o2.c(R.id.selectedTermSelectorBar, viewInflate);
        if (qSegmentedControl == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.selectedTermSelectorBar)));
        }
        com.quizlet.features.setpage.databinding.b bVar = new com.quizlet.features.setpage.databinding.b((ConstraintLayout) viewInflate, qSegmentedControl);
        Intrinsics.checkNotNullExpressionValue(bVar, "inflate(...)");
        return bVar;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        ((com.quizlet.features.setpage.databinding.b) J()).b.setOnCheckedChangedListener(this.k);
        J viewLifecycleOwner = getViewLifecycleOwner();
        Intrinsics.checkNotNullExpressionValue(viewLifecycleOwner, "getViewLifecycleOwner(...)");
        E.A(p0.h(viewLifecycleOwner), null, null, new b(this, null), 3);
    }
}
