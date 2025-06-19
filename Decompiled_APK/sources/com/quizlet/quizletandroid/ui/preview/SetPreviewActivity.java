package com.quizlet.quizletandroid.ui.preview;

import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ProgressBar;
import androidx.activity.RunnableC0043o;
import androidx.activity.v;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.recyclerview.widget.AbstractC1381n0;
import androidx.recyclerview.widget.RecyclerView;
import androidx.recyclerview.widget.T;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3188k6;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.data.repository.folderwithcreatorinclass.e;
import com.quizlet.features.infra.legacyadapter.layoutmanager.HorizontalScalingLinearLayoutManager;
import com.quizlet.features.setpage.SetPageActivity;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.g0;
import com.quizlet.quizletandroid.ui.preview.dataclass.f;
import com.quizlet.quizletandroid.ui.preview.viewmodel.g;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class SetPreviewActivity extends com.quizlet.ads.ui.activity.d {
    public static final String u;
    public com.quizlet.qutils.image.loading.a q;
    public final e r;
    public com.quizlet.quizletandroid.ui.group.classcontent.adapter.a s;
    public final T t;

    static {
        Intrinsics.checkNotNullExpressionValue("SearchActivity", "getSimpleName(...)");
        u = "SearchActivity";
    }

    public SetPreviewActivity() {
        super(4);
        this.r = new e(K.a(g.class), new c(this, 1), new c(this, 0), new c(this, 2));
        this.t = new T(1);
    }

    @Override // com.quizlet.baseui.base.b
    public final String D() {
        return u;
    }

    @Override // com.quizlet.baseui.base.f
    public final androidx.viewbinding.a N() {
        View viewInflate = getLayoutInflater().inflate(R.layout.search_set_preview_activity, (ViewGroup) null, false);
        int i = R.id.error_empty_state;
        QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.error_empty_state, viewInflate);
        if (qTextView != null) {
            i = R.id.exit_button;
            QButton qButton = (QButton) AbstractC3375o2.c(R.id.exit_button, viewInflate);
            if (qButton != null) {
                i = R.id.learn_button;
                QButton qButton2 = (QButton) AbstractC3375o2.c(R.id.learn_button, viewInflate);
                if (qButton2 != null) {
                    i = R.id.onboarding;
                    SetPreviewOnboarding setPreviewOnboarding = (SetPreviewOnboarding) AbstractC3375o2.c(R.id.onboarding, viewInflate);
                    if (setPreviewOnboarding != null) {
                        i = R.id.progress_bar;
                        ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.progress_bar, viewInflate);
                        if (progressBar != null) {
                            i = R.id.search_set_preview_recycler_view;
                            RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.search_set_preview_recycler_view, viewInflate);
                            if (recyclerView != null) {
                                g0 g0Var = new g0((ConstraintLayout) viewInflate, qTextView, qButton, qButton2, setPreviewOnboarding, progressBar, recyclerView);
                                Intrinsics.checkNotNullExpressionValue(g0Var, "inflate(...)");
                                return g0Var;
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final g b0() {
        return (g) this.r.getValue();
    }

    public final void c0(boolean z) {
        QButton learnButton = ((g0) K()).d;
        Intrinsics.checkNotNullExpressionValue(learnButton, "learnButton");
        learnButton.setVisibility(z ? 0 : 8);
        RecyclerView searchSetPreviewRecyclerView = ((g0) K()).g;
        Intrinsics.checkNotNullExpressionValue(searchSetPreviewRecyclerView, "searchSetPreviewRecyclerView");
        searchSetPreviewRecyclerView.setVisibility(z ? 0 : 8);
    }

    @Override // com.quizlet.ads.ui.activity.d, com.quizlet.baseui.base.f, com.quizlet.baseui.base.b, androidx.fragment.app.I, androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        v.b(this, null, 3);
        ConstraintLayout constraintLayout = ((g0) K()).a;
        Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
        AbstractC3188k6.a(constraintLayout);
        com.quizlet.qutils.image.loading.a aVar = this.q;
        if (aVar == null) {
            Intrinsics.m("imageLoader");
            throw null;
        }
        this.s = new com.quizlet.quizletandroid.ui.group.classcontent.adapter.a(aVar);
        g0 g0Var = (g0) K();
        final int i = 0;
        g0Var.c.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.preview.a
            public final /* synthetic */ SetPreviewActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                SetPreviewActivity setPreviewActivity = this.b;
                switch (i) {
                    case 0:
                        String str = SetPreviewActivity.u;
                        setPreviewActivity.b0().h.j(com.quizlet.quizletandroid.ui.preview.dataclass.d.a);
                        return;
                    case 1:
                        String str2 = SetPreviewActivity.u;
                        RecyclerView searchSetPreviewRecyclerView = ((g0) setPreviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(searchSetPreviewRecyclerView, "searchSetPreviewRecyclerView");
                        AbstractC1381n0 layoutManager = searchSetPreviewRecyclerView.getLayoutManager();
                        Intrinsics.e(layoutManager, "null cannot be cast to non-null type com.quizlet.features.infra.legacyadapter.layoutmanager.HorizontalScalingLinearLayoutManager");
                        HorizontalScalingLinearLayoutManager horizontalScalingLinearLayoutManager = (HorizontalScalingLinearLayoutManager) layoutManager;
                        View viewW0 = horizontalScalingLinearLayoutManager.W0(0, horizontalScalingLinearLayoutManager.v(), true, false);
                        int iK = viewW0 == null ? -1 : AbstractC1381n0.K(viewW0);
                        com.quizlet.quizletandroid.ui.group.classcontent.adapter.a aVar2 = setPreviewActivity.s;
                        if (aVar2 == null) {
                            Intrinsics.m("setPreviewAdapter");
                            throw null;
                        }
                        long j = ((com.quizlet.quizletandroid.ui.preview.dataclass.a) aVar2.d(iK)).a;
                        g gVarB0 = setPreviewActivity.b0();
                        Object objA = gVarB0.c.a("setIds");
                        Intrinsics.e(objA, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Long>");
                        gVarB0.e.E(j, ((List) objA).indexOf(Long.valueOf(j)), null);
                        gVarB0.h.j(new f(j));
                        return;
                    default:
                        String str3 = SetPreviewActivity.u;
                        setPreviewActivity.b0().g.j(Boolean.FALSE);
                        return;
                }
            }
        });
        g0 g0Var2 = (g0) K();
        final int i2 = 1;
        g0Var2.d.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.preview.a
            public final /* synthetic */ SetPreviewActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                SetPreviewActivity setPreviewActivity = this.b;
                switch (i2) {
                    case 0:
                        String str = SetPreviewActivity.u;
                        setPreviewActivity.b0().h.j(com.quizlet.quizletandroid.ui.preview.dataclass.d.a);
                        return;
                    case 1:
                        String str2 = SetPreviewActivity.u;
                        RecyclerView searchSetPreviewRecyclerView = ((g0) setPreviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(searchSetPreviewRecyclerView, "searchSetPreviewRecyclerView");
                        AbstractC1381n0 layoutManager = searchSetPreviewRecyclerView.getLayoutManager();
                        Intrinsics.e(layoutManager, "null cannot be cast to non-null type com.quizlet.features.infra.legacyadapter.layoutmanager.HorizontalScalingLinearLayoutManager");
                        HorizontalScalingLinearLayoutManager horizontalScalingLinearLayoutManager = (HorizontalScalingLinearLayoutManager) layoutManager;
                        View viewW0 = horizontalScalingLinearLayoutManager.W0(0, horizontalScalingLinearLayoutManager.v(), true, false);
                        int iK = viewW0 == null ? -1 : AbstractC1381n0.K(viewW0);
                        com.quizlet.quizletandroid.ui.group.classcontent.adapter.a aVar2 = setPreviewActivity.s;
                        if (aVar2 == null) {
                            Intrinsics.m("setPreviewAdapter");
                            throw null;
                        }
                        long j = ((com.quizlet.quizletandroid.ui.preview.dataclass.a) aVar2.d(iK)).a;
                        g gVarB0 = setPreviewActivity.b0();
                        Object objA = gVarB0.c.a("setIds");
                        Intrinsics.e(objA, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Long>");
                        gVarB0.e.E(j, ((List) objA).indexOf(Long.valueOf(j)), null);
                        gVarB0.h.j(new f(j));
                        return;
                    default:
                        String str3 = SetPreviewActivity.u;
                        setPreviewActivity.b0().g.j(Boolean.FALSE);
                        return;
                }
            }
        });
        g0 g0Var3 = (g0) K();
        final int i3 = 2;
        g0Var3.e.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.quizletandroid.ui.preview.a
            public final /* synthetic */ SetPreviewActivity b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view) {
                SetPreviewActivity setPreviewActivity = this.b;
                switch (i3) {
                    case 0:
                        String str = SetPreviewActivity.u;
                        setPreviewActivity.b0().h.j(com.quizlet.quizletandroid.ui.preview.dataclass.d.a);
                        return;
                    case 1:
                        String str2 = SetPreviewActivity.u;
                        RecyclerView searchSetPreviewRecyclerView = ((g0) setPreviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(searchSetPreviewRecyclerView, "searchSetPreviewRecyclerView");
                        AbstractC1381n0 layoutManager = searchSetPreviewRecyclerView.getLayoutManager();
                        Intrinsics.e(layoutManager, "null cannot be cast to non-null type com.quizlet.features.infra.legacyadapter.layoutmanager.HorizontalScalingLinearLayoutManager");
                        HorizontalScalingLinearLayoutManager horizontalScalingLinearLayoutManager = (HorizontalScalingLinearLayoutManager) layoutManager;
                        View viewW0 = horizontalScalingLinearLayoutManager.W0(0, horizontalScalingLinearLayoutManager.v(), true, false);
                        int iK = viewW0 == null ? -1 : AbstractC1381n0.K(viewW0);
                        com.quizlet.quizletandroid.ui.group.classcontent.adapter.a aVar2 = setPreviewActivity.s;
                        if (aVar2 == null) {
                            Intrinsics.m("setPreviewAdapter");
                            throw null;
                        }
                        long j = ((com.quizlet.quizletandroid.ui.preview.dataclass.a) aVar2.d(iK)).a;
                        g gVarB0 = setPreviewActivity.b0();
                        Object objA = gVarB0.c.a("setIds");
                        Intrinsics.e(objA, "null cannot be cast to non-null type kotlin.collections.List<kotlin.Long>");
                        gVarB0.e.E(j, ((List) objA).indexOf(Long.valueOf(j)), null);
                        gVarB0.h.j(new f(j));
                        return;
                    default:
                        String str3 = SetPreviewActivity.u;
                        setPreviewActivity.b0().g.j(Boolean.FALSE);
                        return;
                }
            }
        });
        RecyclerView searchSetPreviewRecyclerView = ((g0) K()).g;
        Intrinsics.checkNotNullExpressionValue(searchSetPreviewRecyclerView, "searchSetPreviewRecyclerView");
        com.quizlet.quizletandroid.ui.group.classcontent.adapter.a aVar2 = this.s;
        if (aVar2 == null) {
            Intrinsics.m("setPreviewAdapter");
            throw null;
        }
        searchSetPreviewRecyclerView.setAdapter(aVar2);
        searchSetPreviewRecyclerView.setLayoutManager(new HorizontalScalingLinearLayoutManager(this));
        this.t.a(searchSetPreviewRecyclerView);
        final int i4 = 1;
        b0().g.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(12, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.preview.b
            public final /* synthetic */ SetPreviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                SetPreviewActivity setPreviewActivity = this.b;
                switch (i4) {
                    case 0:
                        com.quizlet.quizletandroid.ui.preview.dataclass.e eVar = (com.quizlet.quizletandroid.ui.preview.dataclass.e) obj;
                        String str = SetPreviewActivity.u;
                        if (eVar instanceof f) {
                            com.quizlet.features.setpage.e eVar2 = SetPageActivity.h1;
                            setPreviewActivity.startActivity(com.quizlet.features.setpage.e.c(28, ((f) eVar).a, setPreviewActivity));
                        } else {
                            if (!(eVar instanceof com.quizlet.quizletandroid.ui.preview.dataclass.d)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            setPreviewActivity.finish();
                        }
                        return Unit.a;
                    case 1:
                        Boolean bool = (Boolean) obj;
                        String str2 = SetPreviewActivity.u;
                        Intrinsics.d(bool);
                        boolean zBooleanValue = bool.booleanValue();
                        SetPreviewOnboarding onboarding = ((g0) setPreviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(onboarding, "onboarding");
                        onboarding.setVisibility(zBooleanValue ? 0 : 8);
                        return Unit.a;
                    case 2:
                        Integer num = (Integer) obj;
                        String str3 = SetPreviewActivity.u;
                        Intrinsics.d(num);
                        int iIntValue = num.intValue();
                        RecyclerView searchSetPreviewRecyclerView2 = ((g0) setPreviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(searchSetPreviewRecyclerView2, "searchSetPreviewRecyclerView");
                        searchSetPreviewRecyclerView2.setVisibility(0);
                        searchSetPreviewRecyclerView2.k0(iIntValue);
                        searchSetPreviewRecyclerView2.post(new RunnableC0043o(searchSetPreviewRecyclerView2, iIntValue, setPreviewActivity, 8));
                        return Unit.a;
                    default:
                        com.quizlet.quizletandroid.ui.preview.viewmodel.d dVar = (com.quizlet.quizletandroid.ui.preview.viewmodel.d) obj;
                        String str4 = SetPreviewActivity.u;
                        Intrinsics.d(dVar);
                        setPreviewActivity.getClass();
                        if (dVar instanceof com.quizlet.quizletandroid.ui.preview.viewmodel.c) {
                            setPreviewActivity.c0(true);
                            ((g0) setPreviewActivity.K()).f.setVisibility(8);
                            ((g0) setPreviewActivity.K()).b.setVisibility(8);
                            com.quizlet.quizletandroid.ui.group.classcontent.adapter.a aVar3 = setPreviewActivity.s;
                            if (aVar3 == null) {
                                Intrinsics.m("setPreviewAdapter");
                                throw null;
                            }
                            aVar3.f(((com.quizlet.quizletandroid.ui.preview.viewmodel.c) dVar).a);
                        } else if (dVar instanceof com.quizlet.quizletandroid.ui.preview.viewmodel.a) {
                            setPreviewActivity.c0(false);
                            ((g0) setPreviewActivity.K()).b.setVisibility(8);
                            ((g0) setPreviewActivity.K()).f.setVisibility(0);
                        } else {
                            if (!Intrinsics.b(dVar, com.quizlet.quizletandroid.ui.preview.viewmodel.b.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            setPreviewActivity.c0(false);
                            ((g0) setPreviewActivity.K()).f.setVisibility(8);
                            ((g0) setPreviewActivity.K()).b.setVisibility(0);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i5 = 2;
        b0().i.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(12, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.preview.b
            public final /* synthetic */ SetPreviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                SetPreviewActivity setPreviewActivity = this.b;
                switch (i5) {
                    case 0:
                        com.quizlet.quizletandroid.ui.preview.dataclass.e eVar = (com.quizlet.quizletandroid.ui.preview.dataclass.e) obj;
                        String str = SetPreviewActivity.u;
                        if (eVar instanceof f) {
                            com.quizlet.features.setpage.e eVar2 = SetPageActivity.h1;
                            setPreviewActivity.startActivity(com.quizlet.features.setpage.e.c(28, ((f) eVar).a, setPreviewActivity));
                        } else {
                            if (!(eVar instanceof com.quizlet.quizletandroid.ui.preview.dataclass.d)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            setPreviewActivity.finish();
                        }
                        return Unit.a;
                    case 1:
                        Boolean bool = (Boolean) obj;
                        String str2 = SetPreviewActivity.u;
                        Intrinsics.d(bool);
                        boolean zBooleanValue = bool.booleanValue();
                        SetPreviewOnboarding onboarding = ((g0) setPreviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(onboarding, "onboarding");
                        onboarding.setVisibility(zBooleanValue ? 0 : 8);
                        return Unit.a;
                    case 2:
                        Integer num = (Integer) obj;
                        String str3 = SetPreviewActivity.u;
                        Intrinsics.d(num);
                        int iIntValue = num.intValue();
                        RecyclerView searchSetPreviewRecyclerView2 = ((g0) setPreviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(searchSetPreviewRecyclerView2, "searchSetPreviewRecyclerView");
                        searchSetPreviewRecyclerView2.setVisibility(0);
                        searchSetPreviewRecyclerView2.k0(iIntValue);
                        searchSetPreviewRecyclerView2.post(new RunnableC0043o(searchSetPreviewRecyclerView2, iIntValue, setPreviewActivity, 8));
                        return Unit.a;
                    default:
                        com.quizlet.quizletandroid.ui.preview.viewmodel.d dVar = (com.quizlet.quizletandroid.ui.preview.viewmodel.d) obj;
                        String str4 = SetPreviewActivity.u;
                        Intrinsics.d(dVar);
                        setPreviewActivity.getClass();
                        if (dVar instanceof com.quizlet.quizletandroid.ui.preview.viewmodel.c) {
                            setPreviewActivity.c0(true);
                            ((g0) setPreviewActivity.K()).f.setVisibility(8);
                            ((g0) setPreviewActivity.K()).b.setVisibility(8);
                            com.quizlet.quizletandroid.ui.group.classcontent.adapter.a aVar3 = setPreviewActivity.s;
                            if (aVar3 == null) {
                                Intrinsics.m("setPreviewAdapter");
                                throw null;
                            }
                            aVar3.f(((com.quizlet.quizletandroid.ui.preview.viewmodel.c) dVar).a);
                        } else if (dVar instanceof com.quizlet.quizletandroid.ui.preview.viewmodel.a) {
                            setPreviewActivity.c0(false);
                            ((g0) setPreviewActivity.K()).b.setVisibility(8);
                            ((g0) setPreviewActivity.K()).f.setVisibility(0);
                        } else {
                            if (!Intrinsics.b(dVar, com.quizlet.quizletandroid.ui.preview.viewmodel.b.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            setPreviewActivity.c0(false);
                            ((g0) setPreviewActivity.K()).f.setVisibility(8);
                            ((g0) setPreviewActivity.K()).b.setVisibility(0);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i6 = 3;
        b0().f.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(12, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.preview.b
            public final /* synthetic */ SetPreviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                SetPreviewActivity setPreviewActivity = this.b;
                switch (i6) {
                    case 0:
                        com.quizlet.quizletandroid.ui.preview.dataclass.e eVar = (com.quizlet.quizletandroid.ui.preview.dataclass.e) obj;
                        String str = SetPreviewActivity.u;
                        if (eVar instanceof f) {
                            com.quizlet.features.setpage.e eVar2 = SetPageActivity.h1;
                            setPreviewActivity.startActivity(com.quizlet.features.setpage.e.c(28, ((f) eVar).a, setPreviewActivity));
                        } else {
                            if (!(eVar instanceof com.quizlet.quizletandroid.ui.preview.dataclass.d)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            setPreviewActivity.finish();
                        }
                        return Unit.a;
                    case 1:
                        Boolean bool = (Boolean) obj;
                        String str2 = SetPreviewActivity.u;
                        Intrinsics.d(bool);
                        boolean zBooleanValue = bool.booleanValue();
                        SetPreviewOnboarding onboarding = ((g0) setPreviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(onboarding, "onboarding");
                        onboarding.setVisibility(zBooleanValue ? 0 : 8);
                        return Unit.a;
                    case 2:
                        Integer num = (Integer) obj;
                        String str3 = SetPreviewActivity.u;
                        Intrinsics.d(num);
                        int iIntValue = num.intValue();
                        RecyclerView searchSetPreviewRecyclerView2 = ((g0) setPreviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(searchSetPreviewRecyclerView2, "searchSetPreviewRecyclerView");
                        searchSetPreviewRecyclerView2.setVisibility(0);
                        searchSetPreviewRecyclerView2.k0(iIntValue);
                        searchSetPreviewRecyclerView2.post(new RunnableC0043o(searchSetPreviewRecyclerView2, iIntValue, setPreviewActivity, 8));
                        return Unit.a;
                    default:
                        com.quizlet.quizletandroid.ui.preview.viewmodel.d dVar = (com.quizlet.quizletandroid.ui.preview.viewmodel.d) obj;
                        String str4 = SetPreviewActivity.u;
                        Intrinsics.d(dVar);
                        setPreviewActivity.getClass();
                        if (dVar instanceof com.quizlet.quizletandroid.ui.preview.viewmodel.c) {
                            setPreviewActivity.c0(true);
                            ((g0) setPreviewActivity.K()).f.setVisibility(8);
                            ((g0) setPreviewActivity.K()).b.setVisibility(8);
                            com.quizlet.quizletandroid.ui.group.classcontent.adapter.a aVar3 = setPreviewActivity.s;
                            if (aVar3 == null) {
                                Intrinsics.m("setPreviewAdapter");
                                throw null;
                            }
                            aVar3.f(((com.quizlet.quizletandroid.ui.preview.viewmodel.c) dVar).a);
                        } else if (dVar instanceof com.quizlet.quizletandroid.ui.preview.viewmodel.a) {
                            setPreviewActivity.c0(false);
                            ((g0) setPreviewActivity.K()).b.setVisibility(8);
                            ((g0) setPreviewActivity.K()).f.setVisibility(0);
                        } else {
                            if (!Intrinsics.b(dVar, com.quizlet.quizletandroid.ui.preview.viewmodel.b.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            setPreviewActivity.c0(false);
                            ((g0) setPreviewActivity.K()).f.setVisibility(8);
                            ((g0) setPreviewActivity.K()).b.setVisibility(0);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i7 = 0;
        b0().h.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(12, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.preview.b
            public final /* synthetic */ SetPreviewActivity b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                SetPreviewActivity setPreviewActivity = this.b;
                switch (i7) {
                    case 0:
                        com.quizlet.quizletandroid.ui.preview.dataclass.e eVar = (com.quizlet.quizletandroid.ui.preview.dataclass.e) obj;
                        String str = SetPreviewActivity.u;
                        if (eVar instanceof f) {
                            com.quizlet.features.setpage.e eVar2 = SetPageActivity.h1;
                            setPreviewActivity.startActivity(com.quizlet.features.setpage.e.c(28, ((f) eVar).a, setPreviewActivity));
                        } else {
                            if (!(eVar instanceof com.quizlet.quizletandroid.ui.preview.dataclass.d)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            setPreviewActivity.finish();
                        }
                        return Unit.a;
                    case 1:
                        Boolean bool = (Boolean) obj;
                        String str2 = SetPreviewActivity.u;
                        Intrinsics.d(bool);
                        boolean zBooleanValue = bool.booleanValue();
                        SetPreviewOnboarding onboarding = ((g0) setPreviewActivity.K()).e;
                        Intrinsics.checkNotNullExpressionValue(onboarding, "onboarding");
                        onboarding.setVisibility(zBooleanValue ? 0 : 8);
                        return Unit.a;
                    case 2:
                        Integer num = (Integer) obj;
                        String str3 = SetPreviewActivity.u;
                        Intrinsics.d(num);
                        int iIntValue = num.intValue();
                        RecyclerView searchSetPreviewRecyclerView2 = ((g0) setPreviewActivity.K()).g;
                        Intrinsics.checkNotNullExpressionValue(searchSetPreviewRecyclerView2, "searchSetPreviewRecyclerView");
                        searchSetPreviewRecyclerView2.setVisibility(0);
                        searchSetPreviewRecyclerView2.k0(iIntValue);
                        searchSetPreviewRecyclerView2.post(new RunnableC0043o(searchSetPreviewRecyclerView2, iIntValue, setPreviewActivity, 8));
                        return Unit.a;
                    default:
                        com.quizlet.quizletandroid.ui.preview.viewmodel.d dVar = (com.quizlet.quizletandroid.ui.preview.viewmodel.d) obj;
                        String str4 = SetPreviewActivity.u;
                        Intrinsics.d(dVar);
                        setPreviewActivity.getClass();
                        if (dVar instanceof com.quizlet.quizletandroid.ui.preview.viewmodel.c) {
                            setPreviewActivity.c0(true);
                            ((g0) setPreviewActivity.K()).f.setVisibility(8);
                            ((g0) setPreviewActivity.K()).b.setVisibility(8);
                            com.quizlet.quizletandroid.ui.group.classcontent.adapter.a aVar3 = setPreviewActivity.s;
                            if (aVar3 == null) {
                                Intrinsics.m("setPreviewAdapter");
                                throw null;
                            }
                            aVar3.f(((com.quizlet.quizletandroid.ui.preview.viewmodel.c) dVar).a);
                        } else if (dVar instanceof com.quizlet.quizletandroid.ui.preview.viewmodel.a) {
                            setPreviewActivity.c0(false);
                            ((g0) setPreviewActivity.K()).b.setVisibility(8);
                            ((g0) setPreviewActivity.K()).f.setVisibility(0);
                        } else {
                            if (!Intrinsics.b(dVar, com.quizlet.quizletandroid.ui.preview.viewmodel.b.a)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            setPreviewActivity.c0(false);
                            ((g0) setPreviewActivity.K()).f.setVisibility(8);
                            ((g0) setPreviewActivity.K()).b.setVisibility(0);
                        }
                        return Unit.a;
                }
            }
        }));
        if (bundle != null) {
            int i8 = bundle.getInt("currentPos");
            RecyclerView searchSetPreviewRecyclerView2 = ((g0) K()).g;
            Intrinsics.checkNotNullExpressionValue(searchSetPreviewRecyclerView2, "searchSetPreviewRecyclerView");
            searchSetPreviewRecyclerView2.setVisibility(0);
            searchSetPreviewRecyclerView2.k0(i8);
            searchSetPreviewRecyclerView2.post(new RunnableC0043o(searchSetPreviewRecyclerView2, i8, this, 8));
        }
    }

    @Override // androidx.activity.s, androidx.core.app.AbstractActivityC1021h, android.app.Activity
    public final void onSaveInstanceState(Bundle outState) {
        Intrinsics.checkNotNullParameter(outState, "outState");
        super.onSaveInstanceState(outState);
        AbstractC1381n0 layoutManager = ((g0) K()).g.getLayoutManager();
        Intrinsics.e(layoutManager, "null cannot be cast to non-null type com.quizlet.features.infra.legacyadapter.layoutmanager.HorizontalScalingLinearLayoutManager");
        outState.putInt("currentPos", ((HorizontalScalingLinearLayoutManager) layoutManager).T0());
    }
}
