package com.quizlet.quizletandroid.ui.activitycenter.fragments;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import androidx.appcompat.app.AbstractActivityC0055k;
import androidx.appcompat.widget.Toolbar;
import androidx.compose.ui.node.B;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.I;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.C4616u;
import com.quizlet.quizletandroid.databinding.J;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class ActivityCenterFragment extends Hilt_ActivityCenterFragment<C4616u> {
    public static final String n;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e k;
    public c l;
    public final u m;

    static {
        Intrinsics.checkNotNullExpressionValue("ActivityCenterFragment", "getSimpleName(...)");
        n = "ActivityCenterFragment";
    }

    public ActivityCenterFragment() {
        k kVarA = l.a(m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new com.quizlet.login.recovery.forgotpassword.ui.e(this, 2), 3));
        this.j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a.class), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 2), new androidx.credentials.playservices.controllers.BeginSignIn.d(29, this, kVarA), new com.quizlet.login.recovery.forgotpassword.ui.f(kVarA, 3));
        this.k = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.features.infra.snackbar.viewmodel.c.class), new d(this, 0), new d(this, 2), new d(this, 1));
        this.m = l.b(new com.quizlet.login.magiclink.ui.e(this, 6));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return n;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_activity_center, viewGroup, false);
        int i = R.id.contentCardsContainer;
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.contentCardsContainer, viewInflate);
        if (frameLayout != null) {
            i = R.id.toolbarLayout;
            View viewC = AbstractC3375o2.c(R.id.toolbarLayout, viewInflate);
            if (viewC != null) {
                C4616u c4616u = new C4616u((ConstraintLayout) viewInflate, frameLayout, J.a(viewC));
                Intrinsics.checkNotNullExpressionValue(c4616u, "inflate(...)");
                return c4616u;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.quizletandroid.ui.activitycenter.fragments.Hilt_ActivityCenterFragment, com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        super.onAttach(context);
        androidx.savedstate.f parentFragment = getParentFragment();
        this.l = parentFragment instanceof c ? (c) parentFragment : null;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.j;
        ((com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a) eVar.getValue()).g.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(7, new com.quizlet.login.common.navigation.d(1, (com.quizlet.features.infra.snackbar.viewmodel.a) this.k.getValue(), com.quizlet.features.infra.snackbar.viewmodel.a.class, "onDataReceived", "onDataReceived(Lcom/quizlet/features/infra/snackbar/ShowSnackbarData;)V", 0, 14)));
        ((com.quizlet.quizletandroid.ui.activitycenter.viewmodels.a) eVar.getValue()).i.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(7, new com.quizlet.features.folders.composables.J(this, 28)));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDetach() {
        super.onDetach();
        this.l = null;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        if (((Boolean) this.m.getValue()).booleanValue()) {
            Toolbar toolbar = ((C4616u) J()).c.c;
            Intrinsics.checkNotNullExpressionValue(toolbar, "toolbar");
            toolbar.setVisibility(0);
            Intrinsics.checkNotNullParameter(this, "<this>");
            I activity = getActivity();
            Intrinsics.e(activity, "null cannot be cast to non-null type androidx.appcompat.app.AppCompatActivity");
            Toolbar toolbar2 = ((C4616u) J()).c.c;
            Intrinsics.checkNotNullExpressionValue(toolbar2, "toolbar");
            ((AbstractActivityC0055k) activity).v(toolbar2);
            requireActivity().setTitle(R.string.activity_center_title);
        } else {
            Toolbar toolbar3 = ((C4616u) J()).c.c;
            Intrinsics.checkNotNullExpressionValue(toolbar3, "toolbar");
            toolbar3.setVisibility(8);
        }
        ActivityCenterContentCardsFragment activityCenterContentCardsFragment = new ActivityCenterContentCardsFragment();
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        C1121a c1121aB = B.b(childFragmentManager, childFragmentManager);
        c1121aB.i(R.id.contentCardsContainer, activityCenterContentCardsFragment, ActivityCenterContentCardsFragment.j, 1);
        c1121aB.g();
    }
}
