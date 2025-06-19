package com.quizlet.explanations.textbook.exercisedetail.ui;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.ui.node.B;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.FragmentContainerView;
import androidx.lifecycle.J;
import androidx.lifecycle.X;
import androidx.lifecycle.p0;
import androidx.navigation.U;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.C1370i;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.explanations.solution.fragments.ExplanationsSolutionFragment;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.explanations.textbook.exercisedetail.data.ExerciseDetailSetupState;
import com.quizlet.explanations.textbook.ui.TextbookActivity;
import com.quizlet.generated.enums.y1;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes2.dex */
public final class ExerciseDetailFragment extends Hilt_ExerciseDetailFragment<com.quizlet.explanations.databinding.e> implements com.quizlet.explanations.solution.fragments.a {
    public static final String y;
    public com.google.mlkit.common.sdkinternal.b j;
    public com.google.firebase.crashlytics.internal.settings.b k;
    public com.google.mlkit.common.internal.model.a l;
    public com.google.android.material.shape.e m;
    public com.quizlet.explanations.navigation.b n;
    public final u o = l.b(new a(this, 2));
    public final u p = l.b(new a(this, 3));
    public final u q = l.b(new a(this, 4));
    public final u r = l.b(new a(this, 5));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e s;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e t;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e u;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e v;
    public C1370i w;
    public androidx.activity.result.b x;

    static {
        Intrinsics.checkNotNullExpressionValue("ExerciseDetailFragment", "getSimpleName(...)");
        y = "ExerciseDetailFragment";
    }

    public ExerciseDetailFragment() {
        d dVar = new d(this, 0);
        m mVar = m.c;
        k kVarA = l.a(mVar, new assistantMode.experiments.a(dVar, 19));
        this.s = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.explanations.textbook.exercisedetail.viewmodel.c.class), new C4062f(kVarA, 20), new c(this, kVarA, 1), new C4062f(kVarA, 21));
        k kVarA2 = l.a(mVar, new assistantMode.experiments.a(new d(this, 1), 20));
        this.t = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.explanations.solution.viewmodel.b.class), new C4062f(kVarA2, 22), new c(this, kVarA2, 0), new C4062f(kVarA2, 23));
        this.u = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.explanations.textbook.viewmodel.c.class), new b(this, 0), new b(this, 2), new b(this, 1));
        this.v = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.explanations.textbook.tableofcontents.viewmodel.b.class), new b(this, 3), new b(this, 5), new b(this, 4));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return y;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_exercise_detail, viewGroup, false);
        FragmentContainerView fragmentContainerView = (FragmentContainerView) AbstractC3375o2.c(R.id.solutionsFragment, viewInflate);
        if (fragmentContainerView == null) {
            throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(R.id.solutionsFragment)));
        }
        com.quizlet.explanations.databinding.e eVar = new com.quizlet.explanations.databinding.e((CoordinatorLayout) viewInflate, fragmentContainerView);
        Intrinsics.checkNotNullExpressionValue(eVar, "inflate(...)");
        return eVar;
    }

    public final ExerciseDetailSetupState T() {
        ExerciseDetailSetupState exerciseDetailSetupState = (ExerciseDetailSetupState) requireArguments().getParcelable("exercise_detail_state");
        if (exerciseDetailSetupState != null) {
            return exerciseDetailSetupState;
        }
        throw new IllegalArgumentException("Missing argument: ARG_EXERCISE_DETAIL_STATE");
    }

    public final Intent U() {
        String str = TextbookActivity.r;
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        String id = T().a();
        Intrinsics.checkNotNullParameter(id, "id");
        return okhttp3.internal.platform.m.c(contextRequireContext, new TextbookSetUpState.Exercise(id));
    }

    public final com.quizlet.explanations.textbook.exercisedetail.viewmodel.c V() {
        return (com.quizlet.explanations.textbook.exercisedetail.viewmodel.c) this.s.getValue();
    }

    @Override // com.quizlet.explanations.solution.fragments.a
    public final AbstractC1361d0 j() {
        return (com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.a) this.p.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        V().E(T(), y);
        this.x = registerForActivityResult(new androidx.activity.result.contract.b(4), new androidx.activity.compose.b(this, 3));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onStart() {
        super.onStart();
        com.quizlet.explanations.textbook.viewmodel.c cVar = (com.quizlet.explanations.textbook.viewmodel.c) this.u.getValue();
        boolean z = T() instanceof ExerciseDetailSetupState.DeepLink;
        String studyMaterialId = T().a();
        y1 studyMaterialType = y1.TEXTBOOK_EXERCISE;
        cVar.getClass();
        Intrinsics.checkNotNullParameter(studyMaterialId, "studyMaterialId");
        Intrinsics.checkNotNullParameter(studyMaterialType, "studyMaterialType");
        E.A(p0.j(cVar), null, null, new com.quizlet.explanations.textbook.viewmodel.b(cVar, z, studyMaterialId, studyMaterialType, null), 3);
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        C1370i c1370i = new C1370i(new AbstractC1361d0[0]);
        this.w = c1370i;
        c1370i.d((com.quizlet.explanations.textbook.exercisedetail.recyclerview.header.e) this.o.getValue());
        C1370i c1370i2 = this.w;
        if (c1370i2 == null) {
            Intrinsics.m("concatHeaderAdapter");
            throw null;
        }
        c1370i2.d((com.quizlet.explanations.solution.solutionwall.a) this.r.getValue());
        V().l.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(3, new com.quizlet.explanations.solution.fragments.b(1, this, ExerciseDetailFragment.class, "handleViewState", "handleViewState(Lcom/quizlet/explanations/textbook/exercisedetail/data/ExerciseDetailViewState;)V", 0, 10)));
        ((com.quizlet.explanations.solution.viewmodel.b) this.t.getValue()).h.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(3, new com.quizlet.explanations.solution.fragments.b(1, V(), com.quizlet.explanations.textbook.exercisedetail.viewmodel.c.class, "onUpdateExtraInfoAndFooter", "onUpdateExtraInfoAndFooter(Z)V", 0, 11)));
        V().n.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(3, new com.quizlet.explanations.solution.fragments.b(1, (com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.a) this.p.getValue(), com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.a.class, "submitList", "submitList(Ljava/util/List;)V", 0, 12)));
        V().o.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(3, new com.quizlet.explanations.solution.fragments.b(1, (com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.c) this.q.getValue(), com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.c.class, "submitList", "submitList(Ljava/util/List;)V", 0, 13)));
        X x = V().q;
        J viewLifecycleOwner = getViewLifecycleOwner();
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.u;
        x.f(viewLifecycleOwner, new com.quizlet.explanations.feedback.ui.fragments.c(3, new com.quizlet.explanations.solution.fragments.b(1, (com.quizlet.explanations.textbook.viewmodel.c) eVar.getValue(), com.quizlet.explanations.textbook.viewmodel.c.class, "onShowShareSheet", "onShowShareSheet(Lcom/quizlet/explanations/textbook/data/TextbookShareData;)V", 0, 14)));
        V().r.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(3, new com.quizlet.explanations.solution.fragments.b(1, this, ExerciseDetailFragment.class, "showReportFeedback", "showReportFeedback(Lcom/quizlet/explanations/feedback/data/ExplanationsFeedbackSetUpState;)V", 0, 15)));
        V().s.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(3, new com.quizlet.explanations.solution.fragments.b(1, (com.quizlet.explanations.textbook.viewmodel.c) eVar.getValue(), com.quizlet.explanations.textbook.viewmodel.c.class, "onError", "onError(Lcom/quizlet/uicommon/ui/states/GeneralErrorDialogState;)V", 0, 16)));
        V().p.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(3, new U(this, 20)));
        ExplanationsSolutionFragment explanationsSolutionFragment = new ExplanationsSolutionFragment();
        String str = ExplanationsSolutionFragment.s;
        if (getChildFragmentManager().E(str) == null) {
            AbstractC1136h0 childFragmentManager = getChildFragmentManager();
            C1121a c1121aB = B.b(childFragmentManager, childFragmentManager);
            FragmentContainerView solutionsFragment = ((com.quizlet.explanations.databinding.e) J()).b;
            Intrinsics.checkNotNullExpressionValue(solutionsFragment, "solutionsFragment");
            c1121aB.i(solutionsFragment.getId(), explanationsSolutionFragment, str, 1);
            c1121aB.g();
        }
    }

    @Override // com.quizlet.explanations.solution.fragments.a
    public final AbstractC1361d0 q() {
        return (com.quizlet.explanations.textbook.exercisedetail.recyclerview.footer.c) this.q.getValue();
    }

    @Override // com.quizlet.explanations.solution.fragments.a
    public final C1370i t() {
        C1370i c1370i = this.w;
        if (c1370i != null) {
            return c1370i;
        }
        Intrinsics.m("concatHeaderAdapter");
        throw null;
    }
}
