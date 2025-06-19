package com.quizlet.explanations.feedback.ui.fragments;

import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.FragmentContainerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.baseui.base.BaseFragment;
import com.quizlet.explanations.feedback.data.ExplanationsFeedbackSetUpState;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.l;
import kotlin.m;

@Metadata
/* loaded from: classes2.dex */
public final class ExplanationsFeedbackFragment extends Hilt_ExplanationsFeedbackFragment<com.quizlet.explanations.databinding.g> {
    public static final String l;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e j;
    public ExplanationsFeedbackModalFragment k;

    static {
        Intrinsics.checkNotNullExpressionValue("ExplanationsFeedbackFragment", "getSimpleName(...)");
        l = "ExplanationsFeedbackFragment";
    }

    public ExplanationsFeedbackFragment() {
        kotlin.k kVarA = l.a(m.c, new assistantMode.experiments.a(new assistantMode.experiments.a(this, 13), 14));
        this.j = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.explanations.feedback.viewmodel.a.class), new C4062f(kVarA, 12), new androidx.credentials.playservices.controllers.BeginSignIn.d(20, this, kVarA), new C4062f(kVarA, 13));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return l;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_explanations_feedback, viewGroup, false);
        int i = R.id.back;
        FrameLayout frameLayout = (FrameLayout) AbstractC3375o2.c(R.id.back, viewInflate);
        if (frameLayout != null) {
            i = R.id.fragmentContainer;
            FragmentContainerView fragmentContainerView = (FragmentContainerView) AbstractC3375o2.c(R.id.fragmentContainer, viewInflate);
            if (fragmentContainerView != null) {
                com.quizlet.explanations.databinding.g gVar = new com.quizlet.explanations.databinding.g((LinearLayout) viewInflate, frameLayout, fragmentContainerView);
                Intrinsics.checkNotNullExpressionValue(gVar, "inflate(...)");
                return gVar;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final void T(BaseFragment baseFragment, String str) {
        if (getChildFragmentManager().E(str) != null) {
            return;
        }
        AbstractC1136h0 childFragmentManager = getChildFragmentManager();
        childFragmentManager.getClass();
        C1121a c1121a = new C1121a(childFragmentManager);
        c1121a.m(0, 0);
        c1121a.l(((com.quizlet.explanations.databinding.g) J()).c.getId(), baseFragment, str);
        c1121a.g();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        com.quizlet.explanations.feedback.viewmodel.a aVar = (com.quizlet.explanations.feedback.viewmodel.a) this.j.getValue();
        ExplanationsFeedbackSetUpState state = (ExplanationsFeedbackSetUpState) requireArguments().getParcelable("ARG_SET_UP_STATE");
        if (state == null) {
            throw new IllegalStateException("Missing required argument (ExplanationsFeedbackSetUpState)");
        }
        aVar.getClass();
        Intrinsics.checkNotNullParameter(state, "state");
        aVar.h = state;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.j;
        final int i = 0;
        ((com.quizlet.explanations.feedback.viewmodel.a) eVar.getValue()).f.f(getViewLifecycleOwner(), new c(0, new Function1(this) { // from class: com.quizlet.explanations.feedback.ui.fragments.a
            public final /* synthetic */ ExplanationsFeedbackFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                ExplanationsFeedbackFragment explanationsFeedbackFragment = this.b;
                switch (i) {
                    case 0:
                        com.quizlet.explanations.feedback.data.c cVar = (com.quizlet.explanations.feedback.data.c) obj;
                        String str = ExplanationsFeedbackFragment.l;
                        int i2 = cVar == null ? -1 : b.a[cVar.ordinal()];
                        if (i2 == 1) {
                            explanationsFeedbackFragment.T(new ReportThisContentFragment(), ReportThisContentFragment.k);
                        } else {
                            if (i2 != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            explanationsFeedbackFragment.T(new ThanksForReportingFragment(), ThanksForReportingFragment.k);
                        }
                        return Unit.a;
                    default:
                        ExplanationsFeedbackModalFragment explanationsFeedbackModalFragment = explanationsFeedbackFragment.k;
                        if (explanationsFeedbackModalFragment != null) {
                            explanationsFeedbackModalFragment.H(false, false);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i2 = 1;
        ((com.quizlet.explanations.feedback.viewmodel.a) eVar.getValue()).g.f(getViewLifecycleOwner(), new c(0, new Function1(this) { // from class: com.quizlet.explanations.feedback.ui.fragments.a
            public final /* synthetic */ ExplanationsFeedbackFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                ExplanationsFeedbackFragment explanationsFeedbackFragment = this.b;
                switch (i2) {
                    case 0:
                        com.quizlet.explanations.feedback.data.c cVar = (com.quizlet.explanations.feedback.data.c) obj;
                        String str = ExplanationsFeedbackFragment.l;
                        int i22 = cVar == null ? -1 : b.a[cVar.ordinal()];
                        if (i22 == 1) {
                            explanationsFeedbackFragment.T(new ReportThisContentFragment(), ReportThisContentFragment.k);
                        } else {
                            if (i22 != 2) {
                                throw new NoWhenBranchMatchedException();
                            }
                            explanationsFeedbackFragment.T(new ThanksForReportingFragment(), ThanksForReportingFragment.k);
                        }
                        return Unit.a;
                    default:
                        ExplanationsFeedbackModalFragment explanationsFeedbackModalFragment = explanationsFeedbackFragment.k;
                        if (explanationsFeedbackModalFragment != null) {
                            explanationsFeedbackModalFragment.H(false, false);
                        }
                        return Unit.a;
                }
            }
        }));
        com.quizlet.explanations.databinding.g gVar = (com.quizlet.explanations.databinding.g) J();
        gVar.b.setOnClickListener(new com.braze.ui.inappmessage.d(this, 17));
    }
}
