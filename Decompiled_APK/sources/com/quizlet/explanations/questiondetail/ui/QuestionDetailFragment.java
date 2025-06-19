package com.quizlet.explanations.questiondetail.ui;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.compose.foundation.text.z0;
import androidx.compose.runtime.C0813o0;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import androidx.navigation.compose.C1278k;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.C1370i;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import com.google.android.gms.internal.mlkit_vision_document_scanner.D4;
import com.google.android.gms.internal.mlkit_vision_document_scanner.i7;
import com.onetrust.otpublishers.headless.UI.fragment.C4062f;
import com.quizlet.explanations.questiondetail.data.QuestionDetailSetUpState;
import com.quizlet.explanations.questiondetail.data.i;
import com.quizlet.explanations.textbook.data.TextbookSetUpState;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.k;
import kotlin.l;
import kotlin.m;
import kotlin.u;

@Metadata
/* loaded from: classes2.dex */
public final class QuestionDetailFragment extends Hilt_QuestionDetailFragment<androidx.viewbinding.a> implements com.quizlet.explanations.solution.fragments.a {
    public static final String v;
    public com.quizlet.shared.usecase.folderstudymaterials.d j;
    public com.google.android.material.shape.e k;
    public com.quizlet.shared.usecase.folderstudymaterials.c l;
    public com.quizlet.shared.usecase.studiableMetadata.a m;
    public com.quizlet.explanations.navigation.b n;
    public final u o = l.b(new c(this, 2));
    public final u p = l.b(new c(this, 3));
    public final u q = l.b(new c(this, 4));
    public final com.quizlet.data.repository.folderwithcreatorinclass.e r;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e s;
    public C1370i t;
    public androidx.activity.result.b u;

    static {
        Intrinsics.checkNotNullExpressionValue("QuestionDetailFragment", "getSimpleName(...)");
        v = "QuestionDetailFragment";
    }

    public QuestionDetailFragment() {
        g gVar = new g(this, 0);
        m mVar = m.c;
        k kVarA = l.a(mVar, new assistantMode.experiments.a(gVar, 15));
        this.r = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.explanations.questiondetail.viewmodel.f.class), new C4062f(kVarA, 14), new f(this, kVarA, 1), new C4062f(kVarA, 15));
        int i = 16;
        k kVarA2 = l.a(mVar, new assistantMode.experiments.a(new g(this, 1), i));
        this.s = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.explanations.solution.viewmodel.b.class), new C4062f(kVarA2, i), new f(this, kVarA2, 0), new C4062f(kVarA2, 17));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return v;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        return new com.quizlet.explanations.myexplanations.ui.recyclerview.c(this, 5);
    }

    public final void T(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.Z(1378117182);
        if ((((c0814p.h(this) ? 4 : 2) | i) & 3) == 2 && c0814p.x()) {
            c0814p.Q();
        } else {
            AbstractC3178j5.b(null, false, null, androidx.compose.runtime.internal.e.e(-1916364578, new e(this, 0), c0814p), c0814p, 3072, 7);
        }
        C0813o0 c0813o0R = c0814p.r();
        if (c0813o0R != null) {
            c0813o0R.d = new C1278k(this, i, 2);
        }
    }

    public final com.quizlet.explanations.navigation.b U() {
        com.quizlet.explanations.navigation.b bVar = this.n;
        if (bVar != null) {
            return bVar;
        }
        Intrinsics.m("navigationManager");
        throw null;
    }

    public final Intent V() {
        String str = QuestionDetailActivity.t;
        Context contextRequireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
        QuestionDetailSetUpState questionDetailSetUpState = (QuestionDetailSetUpState) requireArguments().getParcelable("question_detail_set_up_state");
        if (questionDetailSetUpState != null) {
            return i7.a(contextRequireContext, new QuestionDetailSetUpState.WithId(((QuestionDetailSetUpState.WithId) questionDetailSetUpState).a));
        }
        throw new IllegalStateException("Missing required argument (ARG_QUESTION_DETAIL_SET_UP_STATE)");
    }

    public final com.quizlet.explanations.questiondetail.viewmodel.f W() {
        return (com.quizlet.explanations.questiondetail.viewmodel.f) this.r.getValue();
    }

    public final void X(i iVar) {
        if (iVar instanceof com.quizlet.explanations.questiondetail.data.h) {
            com.quizlet.explanations.navigation.b bVarU = U();
            Context contextRequireContext = requireContext();
            Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
            String isbn = ((com.quizlet.explanations.questiondetail.data.h) iVar).a;
            Intrinsics.checkNotNullParameter(isbn, "isbn");
            ((com.quizlet.quizletandroid.ui.navigationmanagers.b) bVarU).c(contextRequireContext, new TextbookSetUpState.TableOfContents(isbn));
            return;
        }
        if (iVar instanceof com.quizlet.explanations.questiondetail.data.g) {
            U();
            Context context = requireContext();
            Intrinsics.checkNotNullExpressionValue(context, "requireContext(...)");
            String str = ((com.quizlet.explanations.questiondetail.data.g) iVar).a;
            Intrinsics.checkNotNullParameter(context, "context");
            context.startActivity(D4.a(context, new GlobalNavReroute.Search(str)));
            return;
        }
        if (!Intrinsics.b(iVar, com.quizlet.explanations.questiondetail.data.f.a)) {
            throw new NoWhenBranchMatchedException();
        }
        requireContext();
        com.quizlet.quizletandroid.ui.navigationmanagers.b bVar = (com.quizlet.quizletandroid.ui.navigationmanagers.b) U();
        com.quizlet.ui.models.webpage.c webPage = com.quizlet.ui.models.webpage.c.c;
        Intrinsics.checkNotNullParameter(webPage, "webPage");
        com.quizlet.quizletandroid.ui.webpages.a.a.c(bVar.a, webPage);
    }

    @Override // com.quizlet.explanations.solution.fragments.a
    public final AbstractC1361d0 j() {
        return (com.quizlet.explanations.questiondetail.recyclerview.a) this.q.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        this.u = registerForActivityResult(new androidx.activity.result.contract.b(4), new androidx.activity.compose.b(this, 2));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        C1370i c1370i = new C1370i(new AbstractC1361d0[0]);
        this.t = c1370i;
        u uVar = this.o;
        c1370i.d((com.quizlet.explanations.questiondetail.recyclerview.d) uVar.getValue());
        C1370i c1370i2 = this.t;
        if (c1370i2 == null) {
            Intrinsics.m("concatHeaderAdapter");
            throw null;
        }
        c1370i2.d((com.quizlet.explanations.solution.solutionwall.a) this.p.getValue());
        W().p.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(1, new z0(1, (com.quizlet.explanations.questiondetail.recyclerview.d) uVar.getValue(), com.quizlet.explanations.questiondetail.recyclerview.d.class, "submitList", "submitList(Ljava/util/List;)V", 0, 16)));
        W().q.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(1, new z0(1, this, QuestionDetailFragment.class, "handleSolutionViewState", "handleSolutionViewState(Lcom/quizlet/explanations/solution/data/SolutionViewState;)V", 0, 17)));
        W().t.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(1, new z0(1, (com.quizlet.explanations.questiondetail.recyclerview.a) this.q.getValue(), com.quizlet.explanations.questiondetail.recyclerview.a.class, "submitList", "submitList(Ljava/util/List;)V", 0, 18)));
        W().u.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(1, new z0(1, this, QuestionDetailFragment.class, "showImageOverlay", "showImageOverlay(Ljava/lang/String;)V", 0, 19)));
        W().v.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(1, new z0(1, this, QuestionDetailFragment.class, "showErrorState", "showErrorState(Lcom/quizlet/uicommon/ui/states/GeneralErrorDialogState;)V", 0, 20)));
        W().w.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(1, new z0(1, this, QuestionDetailFragment.class, "showShareSheet", "showShareSheet(Lcom/quizlet/explanations/sharing/ExplanationsShareResData;)V", 0, 21)));
        W().x.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(1, new z0(1, this, QuestionDetailFragment.class, "showReportFeedback", "showReportFeedback(Lcom/quizlet/explanations/feedback/data/ExplanationsFeedbackSetUpState;)V", 0, 22)));
        W().y.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(1, new z0(1, this, QuestionDetailFragment.class, "handleNavigation", "handleNavigation(Lcom/quizlet/explanations/questiondetail/data/QuestionDetailNavigationEvent;)V", 0, 23)));
        ((com.quizlet.explanations.solution.viewmodel.b) this.s.getValue()).h.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(1, new z0(1, W(), com.quizlet.explanations.questiondetail.viewmodel.f.class, "onStepsRevealed", "onStepsRevealed(Z)V", 0, 24)));
    }

    @Override // com.quizlet.explanations.solution.fragments.a
    public final AbstractC1361d0 q() {
        return null;
    }

    @Override // com.quizlet.explanations.solution.fragments.a
    public final C1370i t() {
        C1370i c1370i = this.t;
        if (c1370i != null) {
            return c1370i;
        }
        Intrinsics.m("concatHeaderAdapter");
        throw null;
    }
}
