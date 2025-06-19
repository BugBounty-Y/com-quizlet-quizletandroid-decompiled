package com.quizlet.explanations.solution.fragments;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.lifecycle.J;
import androidx.lifecycle.Y;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.C1370i;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.savedstate.f;
import com.google.android.gms.internal.mlkit_common.u;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.explanations.databinding.h;
import com.quizlet.explanations.solution.recyclerview.step.l;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes2.dex */
public final class ExplanationsSolutionFragment extends Hilt_ExplanationsSolutionFragment<h> {
    public static final String s;
    public final e j = new e(K.a(com.quizlet.explanations.solution.viewmodel.b.class), new c(this, 0), new c(this, 2), new c(this, 1));
    public l k;
    public com.quizlet.explanations.solution.recyclerview.tablayout.a l;
    public com.quizlet.explanations.solution.recyclerview.revealbutton.a m;
    public com.quizlet.explanations.navigation.b n;
    public u o;
    public assistantMode.utils.studiableMetadata.b p;
    public retrofit2.adapter.rxjava3.d q;
    public a r;

    static {
        Intrinsics.checkNotNullExpressionValue("ExplanationsSolutionFragment", "getSimpleName(...)");
        s = "ExplanationsSolutionFragment";
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return s;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_explanations_solution, viewGroup, false);
        int i = R.id.buttonsList;
        RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.buttonsList, viewInflate);
        if (recyclerView != null) {
            i = R.id.solutionsList;
            RecyclerView recyclerView2 = (RecyclerView) AbstractC3375o2.c(R.id.solutionsList, viewInflate);
            if (recyclerView2 != null) {
                h hVar = new h((ConstraintLayout) viewInflate, recyclerView, recyclerView2);
                Intrinsics.checkNotNullExpressionValue(hVar, "inflate(...)");
                return hVar;
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final com.quizlet.explanations.solution.viewmodel.b T() {
        return (com.quizlet.explanations.solution.viewmodel.b) this.j.getValue();
    }

    @Override // com.quizlet.explanations.solution.fragments.Hilt_ExplanationsSolutionFragment, com.quizlet.baseui.base.BaseFragment, com.quizlet.baseui.di.BaseDaggerFragment, androidx.fragment.app.Fragment
    public final void onAttach(Context context) {
        Intrinsics.checkNotNullParameter(context, "context");
        super.onAttach(context);
        f fVarRequireParentFragment = requireParentFragment();
        this.r = fVarRequireParentFragment instanceof a ? (a) fVarRequireParentFragment : null;
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        if (this.p == null) {
            Intrinsics.m("solutionStepsAdapterFactory");
            throw null;
        }
        com.quizlet.explanations.solution.viewmodel.b renderListener = T();
        Intrinsics.checkNotNullParameter(renderListener, "renderListener");
        this.k = new l(renderListener);
        if (this.o == null) {
            Intrinsics.m("solutionTabLayoutAdapterFactory");
            throw null;
        }
        this.l = new com.quizlet.explanations.solution.recyclerview.tablayout.a(AbstractC4178x.h("diffUtilCallback"));
        if (this.q != null) {
            this.m = new com.quizlet.explanations.solution.recyclerview.revealbutton.a(AbstractC4178x.h("diffUtilCallback"));
        } else {
            Intrinsics.m("solutionRevealButtonAdapterFactory");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        ((h) J()).c.setAdapter(null);
        super.onDestroyView();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDetach() {
        this.r = null;
        super.onDetach();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        AbstractC1361d0 abstractC1361d0Q;
        AbstractC1361d0 abstractC1361d0J;
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        Y y = T().d;
        J viewLifecycleOwner = getViewLifecycleOwner();
        com.quizlet.explanations.solution.recyclerview.tablayout.a aVar = this.l;
        if (aVar == null) {
            Intrinsics.m("solutionTabLayoutAdapter");
            throw null;
        }
        y.f(viewLifecycleOwner, new com.quizlet.ads.ui.activity.a(2, new b(1, aVar, com.quizlet.explanations.solution.recyclerview.tablayout.a.class, "submitList", "submitList(Ljava/util/List;)V", 0, 0)));
        T().e.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(2, new b(1, this, ExplanationsSolutionFragment.class, "updateSolutionStepsAdapter", "updateSolutionStepsAdapter(Lcom/quizlet/explanations/solution/viewmodel/SolutionStepItemState;)V", 0, 1)));
        T().f.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(2, new b(1, this, ExplanationsSolutionFragment.class, "refreshStep", "refreshStep(I)V", 0, 2)));
        Y y2 = T().g;
        J viewLifecycleOwner2 = getViewLifecycleOwner();
        com.quizlet.explanations.solution.recyclerview.revealbutton.a aVar2 = this.m;
        if (aVar2 == null) {
            Intrinsics.m("solutionRevealButtonAdapter");
            throw null;
        }
        y2.f(viewLifecycleOwner2, new com.quizlet.ads.ui.activity.a(2, new b(1, aVar2, com.quizlet.explanations.solution.recyclerview.revealbutton.a.class, "submitList", "submitList(Ljava/util/List;)V", 0, 3)));
        T().i.f(getViewLifecycleOwner(), new com.quizlet.ads.ui.activity.a(2, new b(1, this, ExplanationsSolutionFragment.class, "showImageOverlayDialog", "showImageOverlayDialog(Lcom/quizlet/explanations/solution/viewmodel/ImageOverlayEvent;)V", 0, 4)));
        C1370i c1370i = new C1370i(new AbstractC1361d0[0]);
        a aVar3 = this.r;
        if (aVar3 != null) {
            c1370i.d(aVar3.t());
        }
        com.quizlet.explanations.solution.recyclerview.tablayout.a aVar4 = this.l;
        if (aVar4 == null) {
            Intrinsics.m("solutionTabLayoutAdapter");
            throw null;
        }
        c1370i.d(aVar4);
        l lVar = this.k;
        if (lVar == null) {
            Intrinsics.m("solutionStepsAdapter");
            throw null;
        }
        c1370i.d(lVar);
        a aVar5 = this.r;
        if (aVar5 != null && (abstractC1361d0J = aVar5.j()) != null) {
            c1370i.d(abstractC1361d0J);
        }
        ((h) J()).c.setAdapter(c1370i);
        h hVar = (h) J();
        requireContext();
        hVar.c.setLayoutManager(new LinearLayoutManager(1));
        C1370i c1370i2 = new C1370i(new AbstractC1361d0[0]);
        com.quizlet.explanations.solution.recyclerview.revealbutton.a aVar6 = this.m;
        if (aVar6 == null) {
            Intrinsics.m("solutionRevealButtonAdapter");
            throw null;
        }
        c1370i2.d(aVar6);
        a aVar7 = this.r;
        if (aVar7 != null && (abstractC1361d0Q = aVar7.q()) != null) {
            c1370i2.d(abstractC1361d0Q);
        }
        ((h) J()).b.setAdapter(c1370i2);
        h hVar2 = (h) J();
        requireContext();
        hVar2.b.setLayoutManager(new LinearLayoutManager(1));
    }
}
