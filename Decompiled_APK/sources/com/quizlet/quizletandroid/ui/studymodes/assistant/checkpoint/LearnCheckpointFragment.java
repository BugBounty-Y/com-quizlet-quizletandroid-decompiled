package com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.LinearLayout;
import android.widget.RelativeLayout;
import androidx.appcompat.widget.AppCompatTextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3691o6;
import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.appbar.CollapsingToolbarLayout;
import com.quizlet.learn.viewmodel.G;
import com.quizlet.partskit.widgets.QButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.databinding.a0;
import com.quizlet.quizletandroid.ui.common.views.BucketArcProgressBar;
import com.quizlet.quizletandroid.ui.common.views.SegmentedBucketLayout2;
import com.quizlet.uicommon.ui.common.dialogs.ImageOverlayDialogFragment;
import java.util.List;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;

@Metadata
/* loaded from: classes3.dex */
public final class LearnCheckpointFragment extends Hilt_LearnCheckpointFragment<a0> {
    public static final String o;
    public com.quizlet.qutils.image.loading.a j;
    public com.quizlet.quizletandroid.managers.audio.h k;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e l;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e m;
    public C4755a n;

    static {
        Intrinsics.checkNotNullExpressionValue("LearnCheckpointFragment", "getSimpleName(...)");
        o = "LearnCheckpointFragment";
    }

    public LearnCheckpointFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new com.quizlet.login.recovery.forgotpassword.ui.e(new h(this, 3), 23));
        this.l = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d.class), new i(kVarA, 0), new com.quizlet.quizletandroid.ui.activitycenter.fragments.h(this, kVarA, 14), new i(kVarA, 1));
        this.m = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(G.class), new h(this, 0), new h(this, 2), new h(this, 1));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return o;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.new_assistant_checkpoint_fragment, viewGroup, false);
        int i = R.id.assistant_checkpoint_app_bar_layout;
        AppBarLayout appBarLayout = (AppBarLayout) AbstractC3375o2.c(R.id.assistant_checkpoint_app_bar_layout, viewInflate);
        if (appBarLayout != null) {
            i = R.id.assistant_checkpoint_continue_button;
            QButton qButton = (QButton) AbstractC3375o2.c(R.id.assistant_checkpoint_continue_button, viewInflate);
            if (qButton != null) {
                i = R.id.assistant_checkpoint_details_term_list_recycler_view;
                RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.assistant_checkpoint_details_term_list_recycler_view, viewInflate);
                if (recyclerView != null) {
                    i = R.id.assistant_checkpoint_header;
                    View viewC = AbstractC3375o2.c(R.id.assistant_checkpoint_header, viewInflate);
                    if (viewC != null) {
                        int i2 = R.id.assistant_checkpoint_details_bucket_progress_bar;
                        BucketArcProgressBar bucketArcProgressBar = (BucketArcProgressBar) AbstractC3375o2.c(R.id.assistant_checkpoint_details_bucket_progress_bar, viewC);
                        if (bucketArcProgressBar != null) {
                            i2 = R.id.assistant_checkpoint_details_mastery_parent;
                            RelativeLayout relativeLayout = (RelativeLayout) AbstractC3375o2.c(R.id.assistant_checkpoint_details_mastery_parent, viewC);
                            if (relativeLayout != null) {
                                i2 = R.id.assistant_checkpoint_details_mastery_progress_text;
                                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.assistant_checkpoint_details_mastery_progress_text, viewC);
                                if (qTextView != null) {
                                    i2 = R.id.assistant_checkpoint_details_new_bucket_view;
                                    SegmentedBucketLayout2 segmentedBucketLayout2 = (SegmentedBucketLayout2) AbstractC3375o2.c(R.id.assistant_checkpoint_details_new_bucket_view, viewC);
                                    if (segmentedBucketLayout2 != null) {
                                        i2 = R.id.assistant_checkpoint_emoji;
                                        AppCompatTextView appCompatTextView = (AppCompatTextView) AbstractC3375o2.c(R.id.assistant_checkpoint_emoji, viewC);
                                        if (appCompatTextView != null) {
                                            i2 = R.id.assistant_checkpoint_message;
                                            QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.assistant_checkpoint_message, viewC);
                                            if (qTextView2 != null) {
                                                com.onetrust.otpublishers.headless.databinding.d dVar = new com.onetrust.otpublishers.headless.databinding.d((LinearLayout) viewC, bucketArcProgressBar, relativeLayout, qTextView, segmentedBucketLayout2, appCompatTextView, qTextView2);
                                                i = R.id.assistant_checkpoint_header_container;
                                                if (((CoordinatorLayout) AbstractC3375o2.c(R.id.assistant_checkpoint_header_container, viewInflate)) != null) {
                                                    i = R.id.assistant_checkpoint_toolbar;
                                                    CollapsingToolbarLayout collapsingToolbarLayout = (CollapsingToolbarLayout) AbstractC3375o2.c(R.id.assistant_checkpoint_toolbar, viewInflate);
                                                    if (collapsingToolbarLayout != null) {
                                                        a0 a0Var = new a0((ConstraintLayout) viewInflate, appBarLayout, qButton, recyclerView, dVar, collapsingToolbarLayout);
                                                        Intrinsics.checkNotNullExpressionValue(a0Var, "inflate(...)");
                                                        return a0Var;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        throw new NullPointerException("Missing required view with ID: ".concat(viewC.getResources().getResourceName(i2)));
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d T() {
        return (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d) this.l.getValue();
    }

    public final CollapsingToolbarLayout U() {
        CollapsingToolbarLayout assistantCheckpointToolbar = ((a0) J()).f;
        Intrinsics.checkNotNullExpressionValue(assistantCheckpointToolbar, "assistantCheckpointToolbar");
        return assistantCheckpointToolbar;
    }

    public final void V(boolean z) {
        if (getResources().getConfiguration().orientation != 1 || !z) {
            ViewGroup.LayoutParams layoutParams = U().getLayoutParams();
            Intrinsics.e(layoutParams, "null cannot be cast to non-null type com.google.android.material.appbar.AppBarLayout.LayoutParams");
            com.google.android.material.appbar.e eVar = (com.google.android.material.appbar.e) layoutParams;
            eVar.a = 1;
            U().setLayoutParams(eVar);
            return;
        }
        ViewGroup.LayoutParams layoutParams2 = U().getLayoutParams();
        Intrinsics.e(layoutParams2, "null cannot be cast to non-null type com.google.android.material.appbar.AppBarLayout.LayoutParams");
        com.google.android.material.appbar.e eVar2 = (com.google.android.material.appbar.e) layoutParams2;
        eVar2.a = 0;
        U().setLayoutParams(eVar2);
        AppBarLayout assistantCheckpointAppBarLayout = ((a0) J()).b;
        Intrinsics.checkNotNullExpressionValue(assistantCheckpointAppBarLayout, "assistantCheckpointAppBarLayout");
        assistantCheckpointAppBarLayout.setExpanded(true);
    }

    @Override // androidx.fragment.app.Fragment, android.content.ComponentCallbacks
    public final void onConfigurationChanged(Configuration newConfig) {
        Intrinsics.checkNotNullParameter(newConfig, "newConfig");
        super.onConfigurationChanged(newConfig);
        C4755a c4755a = this.n;
        if (c4755a != null) {
            V(c4755a.getItemCount() == 0);
        } else {
            Intrinsics.m("adapter");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        final int i = 0;
        T().d.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(20, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.f
            public final /* synthetic */ LearnCheckpointFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Resources.NotFoundException {
                LearnCheckpointFragment learnCheckpointFragment = this.b;
                switch (i) {
                    case 0:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.a aVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.a) obj;
                        String str = LearnCheckpointFragment.o;
                        Intrinsics.d(aVar);
                        int i2 = aVar.a;
                        String strD = AbstractC3691o6.d(i2);
                        AppCompatTextView assistantCheckpointEmoji = (AppCompatTextView) ((a0) learnCheckpointFragment.J()).e.g;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointEmoji, "assistantCheckpointEmoji");
                        assistantCheckpointEmoji.setText(strD);
                        String string = learnCheckpointFragment.getString(AbstractC3691o6.e(i2));
                        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                        QTextView assistantCheckpointMessage = (QTextView) ((a0) learnCheckpointFragment.J()).e.h;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointMessage, "assistantCheckpointMessage");
                        assistantCheckpointMessage.setText(string);
                        String string2 = learnCheckpointFragment.requireContext().getString(R.string.assistant_checkpoint_details_mastery_text_formatter, Integer.valueOf(i2));
                        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
                        QTextView assistantCheckpointDetailsMasteryProgressText = (QTextView) ((a0) learnCheckpointFragment.J()).e.e;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsMasteryProgressText, "assistantCheckpointDetailsMasteryProgressText");
                        assistantCheckpointDetailsMasteryProgressText.setText(string2);
                        String string3 = learnCheckpointFragment.getString(R.string.new_assistant_checkpoint_details_mastery_text_cd, Integer.valueOf(i2));
                        Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
                        RelativeLayout assistantCheckpointDetailsMasteryParent = (RelativeLayout) ((a0) learnCheckpointFragment.J()).e.b;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsMasteryParent, "assistantCheckpointDetailsMasteryParent");
                        assistantCheckpointDetailsMasteryParent.setContentDescription(string3);
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.n nVar = aVar.b;
                        SegmentedBucketLayout2 assistantCheckpointDetailsNewBucketView = (SegmentedBucketLayout2) ((a0) learnCheckpointFragment.J()).e.f;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsNewBucketView, "assistantCheckpointDetailsNewBucketView");
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o.a;
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar2 = nVar.b;
                        assistantCheckpointDetailsNewBucketView.a(R.plurals.assistant_checkpoint_details_bucket_term, R.plurals.assistant_checkpoint_details_bucket_term_cd, R.attr.iconColorSecondary, nVar.c, oVar2 == oVar, new g(learnCheckpointFragment, 1), oVar);
                        SegmentedBucketLayout2 assistantCheckpointDetailsNewBucketView2 = (SegmentedBucketLayout2) ((a0) learnCheckpointFragment.J()).e.f;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsNewBucketView2, "assistantCheckpointDetailsNewBucketView");
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar3 = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o.b;
                        assistantCheckpointDetailsNewBucketView2.a(R.plurals.assistant_checkpoint_details_bucket_familiar, R.plurals.assistant_checkpoint_details_bucket_familiar_cd, R.attr.iconColorSuccess, nVar.d, oVar2 == oVar3, new g(learnCheckpointFragment, 2), oVar3);
                        BucketArcProgressBar assistantCheckpointDetailsBucketProgressBar = (BucketArcProgressBar) ((a0) learnCheckpointFragment.J()).e.d;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsBucketProgressBar, "assistantCheckpointDetailsBucketProgressBar");
                        float f = nVar.a;
                        Context contextRequireContext = learnCheckpointFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        assistantCheckpointDetailsBucketProgressBar.a(f, com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.colorProgressBar));
                        BucketArcProgressBar assistantCheckpointDetailsBucketProgressBar2 = (BucketArcProgressBar) ((a0) learnCheckpointFragment.J()).e.d;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsBucketProgressBar2, "assistantCheckpointDetailsBucketProgressBar");
                        float f2 = 100 - f;
                        Context contextRequireContext2 = learnCheckpointFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        assistantCheckpointDetailsBucketProgressBar2.a(f2, com.quizlet.themes.extensions.a.a(contextRequireContext2, R.attr.iconColorPrimaryInverse));
                        return Unit.a;
                    case 1:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.l lVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.l) obj;
                        String str2 = LearnCheckpointFragment.o;
                        if (lVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.j) {
                            List list = ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.j) lVar).a;
                            C4755a c4755a = learnCheckpointFragment.n;
                            if (c4755a == null) {
                                Intrinsics.m("adapter");
                                throw null;
                            }
                            c4755a.f(list);
                            learnCheckpointFragment.V(list.isEmpty());
                        }
                        return Unit.a;
                    case 2:
                        ((G) learnCheckpointFragment.m.getValue()).T();
                        return Unit.a;
                    default:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m mVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m) obj;
                        String str3 = LearnCheckpointFragment.o;
                        if (!(mVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        String str4 = mVar.a;
                        if (learnCheckpointFragment.isAdded() && learnCheckpointFragment.getFragmentManager() != null) {
                            String str5 = ImageOverlayDialogFragment.x;
                            AbstractC1136h0 abstractC1136h0RequireFragmentManager = learnCheckpointFragment.requireFragmentManager();
                            Intrinsics.checkNotNullExpressionValue(abstractC1136h0RequireFragmentManager, "requireFragmentManager(...)");
                            com.quizlet.quizletandroid.managers.upgrade.a.i(str4, abstractC1136h0RequireFragmentManager, null);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i2 = 1;
        T().e.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(20, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.f
            public final /* synthetic */ LearnCheckpointFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Resources.NotFoundException {
                LearnCheckpointFragment learnCheckpointFragment = this.b;
                switch (i2) {
                    case 0:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.a aVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.a) obj;
                        String str = LearnCheckpointFragment.o;
                        Intrinsics.d(aVar);
                        int i22 = aVar.a;
                        String strD = AbstractC3691o6.d(i22);
                        AppCompatTextView assistantCheckpointEmoji = (AppCompatTextView) ((a0) learnCheckpointFragment.J()).e.g;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointEmoji, "assistantCheckpointEmoji");
                        assistantCheckpointEmoji.setText(strD);
                        String string = learnCheckpointFragment.getString(AbstractC3691o6.e(i22));
                        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                        QTextView assistantCheckpointMessage = (QTextView) ((a0) learnCheckpointFragment.J()).e.h;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointMessage, "assistantCheckpointMessage");
                        assistantCheckpointMessage.setText(string);
                        String string2 = learnCheckpointFragment.requireContext().getString(R.string.assistant_checkpoint_details_mastery_text_formatter, Integer.valueOf(i22));
                        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
                        QTextView assistantCheckpointDetailsMasteryProgressText = (QTextView) ((a0) learnCheckpointFragment.J()).e.e;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsMasteryProgressText, "assistantCheckpointDetailsMasteryProgressText");
                        assistantCheckpointDetailsMasteryProgressText.setText(string2);
                        String string3 = learnCheckpointFragment.getString(R.string.new_assistant_checkpoint_details_mastery_text_cd, Integer.valueOf(i22));
                        Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
                        RelativeLayout assistantCheckpointDetailsMasteryParent = (RelativeLayout) ((a0) learnCheckpointFragment.J()).e.b;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsMasteryParent, "assistantCheckpointDetailsMasteryParent");
                        assistantCheckpointDetailsMasteryParent.setContentDescription(string3);
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.n nVar = aVar.b;
                        SegmentedBucketLayout2 assistantCheckpointDetailsNewBucketView = (SegmentedBucketLayout2) ((a0) learnCheckpointFragment.J()).e.f;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsNewBucketView, "assistantCheckpointDetailsNewBucketView");
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o.a;
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar2 = nVar.b;
                        assistantCheckpointDetailsNewBucketView.a(R.plurals.assistant_checkpoint_details_bucket_term, R.plurals.assistant_checkpoint_details_bucket_term_cd, R.attr.iconColorSecondary, nVar.c, oVar2 == oVar, new g(learnCheckpointFragment, 1), oVar);
                        SegmentedBucketLayout2 assistantCheckpointDetailsNewBucketView2 = (SegmentedBucketLayout2) ((a0) learnCheckpointFragment.J()).e.f;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsNewBucketView2, "assistantCheckpointDetailsNewBucketView");
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar3 = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o.b;
                        assistantCheckpointDetailsNewBucketView2.a(R.plurals.assistant_checkpoint_details_bucket_familiar, R.plurals.assistant_checkpoint_details_bucket_familiar_cd, R.attr.iconColorSuccess, nVar.d, oVar2 == oVar3, new g(learnCheckpointFragment, 2), oVar3);
                        BucketArcProgressBar assistantCheckpointDetailsBucketProgressBar = (BucketArcProgressBar) ((a0) learnCheckpointFragment.J()).e.d;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsBucketProgressBar, "assistantCheckpointDetailsBucketProgressBar");
                        float f = nVar.a;
                        Context contextRequireContext = learnCheckpointFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        assistantCheckpointDetailsBucketProgressBar.a(f, com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.colorProgressBar));
                        BucketArcProgressBar assistantCheckpointDetailsBucketProgressBar2 = (BucketArcProgressBar) ((a0) learnCheckpointFragment.J()).e.d;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsBucketProgressBar2, "assistantCheckpointDetailsBucketProgressBar");
                        float f2 = 100 - f;
                        Context contextRequireContext2 = learnCheckpointFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        assistantCheckpointDetailsBucketProgressBar2.a(f2, com.quizlet.themes.extensions.a.a(contextRequireContext2, R.attr.iconColorPrimaryInverse));
                        return Unit.a;
                    case 1:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.l lVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.l) obj;
                        String str2 = LearnCheckpointFragment.o;
                        if (lVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.j) {
                            List list = ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.j) lVar).a;
                            C4755a c4755a = learnCheckpointFragment.n;
                            if (c4755a == null) {
                                Intrinsics.m("adapter");
                                throw null;
                            }
                            c4755a.f(list);
                            learnCheckpointFragment.V(list.isEmpty());
                        }
                        return Unit.a;
                    case 2:
                        ((G) learnCheckpointFragment.m.getValue()).T();
                        return Unit.a;
                    default:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m mVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m) obj;
                        String str3 = LearnCheckpointFragment.o;
                        if (!(mVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        String str4 = mVar.a;
                        if (learnCheckpointFragment.isAdded() && learnCheckpointFragment.getFragmentManager() != null) {
                            String str5 = ImageOverlayDialogFragment.x;
                            AbstractC1136h0 abstractC1136h0RequireFragmentManager = learnCheckpointFragment.requireFragmentManager();
                            Intrinsics.checkNotNullExpressionValue(abstractC1136h0RequireFragmentManager, "requireFragmentManager(...)");
                            com.quizlet.quizletandroid.managers.upgrade.a.i(str4, abstractC1136h0RequireFragmentManager, null);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i3 = 2;
        T().f.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(20, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.f
            public final /* synthetic */ LearnCheckpointFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Resources.NotFoundException {
                LearnCheckpointFragment learnCheckpointFragment = this.b;
                switch (i3) {
                    case 0:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.a aVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.a) obj;
                        String str = LearnCheckpointFragment.o;
                        Intrinsics.d(aVar);
                        int i22 = aVar.a;
                        String strD = AbstractC3691o6.d(i22);
                        AppCompatTextView assistantCheckpointEmoji = (AppCompatTextView) ((a0) learnCheckpointFragment.J()).e.g;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointEmoji, "assistantCheckpointEmoji");
                        assistantCheckpointEmoji.setText(strD);
                        String string = learnCheckpointFragment.getString(AbstractC3691o6.e(i22));
                        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                        QTextView assistantCheckpointMessage = (QTextView) ((a0) learnCheckpointFragment.J()).e.h;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointMessage, "assistantCheckpointMessage");
                        assistantCheckpointMessage.setText(string);
                        String string2 = learnCheckpointFragment.requireContext().getString(R.string.assistant_checkpoint_details_mastery_text_formatter, Integer.valueOf(i22));
                        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
                        QTextView assistantCheckpointDetailsMasteryProgressText = (QTextView) ((a0) learnCheckpointFragment.J()).e.e;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsMasteryProgressText, "assistantCheckpointDetailsMasteryProgressText");
                        assistantCheckpointDetailsMasteryProgressText.setText(string2);
                        String string3 = learnCheckpointFragment.getString(R.string.new_assistant_checkpoint_details_mastery_text_cd, Integer.valueOf(i22));
                        Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
                        RelativeLayout assistantCheckpointDetailsMasteryParent = (RelativeLayout) ((a0) learnCheckpointFragment.J()).e.b;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsMasteryParent, "assistantCheckpointDetailsMasteryParent");
                        assistantCheckpointDetailsMasteryParent.setContentDescription(string3);
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.n nVar = aVar.b;
                        SegmentedBucketLayout2 assistantCheckpointDetailsNewBucketView = (SegmentedBucketLayout2) ((a0) learnCheckpointFragment.J()).e.f;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsNewBucketView, "assistantCheckpointDetailsNewBucketView");
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o.a;
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar2 = nVar.b;
                        assistantCheckpointDetailsNewBucketView.a(R.plurals.assistant_checkpoint_details_bucket_term, R.plurals.assistant_checkpoint_details_bucket_term_cd, R.attr.iconColorSecondary, nVar.c, oVar2 == oVar, new g(learnCheckpointFragment, 1), oVar);
                        SegmentedBucketLayout2 assistantCheckpointDetailsNewBucketView2 = (SegmentedBucketLayout2) ((a0) learnCheckpointFragment.J()).e.f;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsNewBucketView2, "assistantCheckpointDetailsNewBucketView");
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar3 = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o.b;
                        assistantCheckpointDetailsNewBucketView2.a(R.plurals.assistant_checkpoint_details_bucket_familiar, R.plurals.assistant_checkpoint_details_bucket_familiar_cd, R.attr.iconColorSuccess, nVar.d, oVar2 == oVar3, new g(learnCheckpointFragment, 2), oVar3);
                        BucketArcProgressBar assistantCheckpointDetailsBucketProgressBar = (BucketArcProgressBar) ((a0) learnCheckpointFragment.J()).e.d;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsBucketProgressBar, "assistantCheckpointDetailsBucketProgressBar");
                        float f = nVar.a;
                        Context contextRequireContext = learnCheckpointFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        assistantCheckpointDetailsBucketProgressBar.a(f, com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.colorProgressBar));
                        BucketArcProgressBar assistantCheckpointDetailsBucketProgressBar2 = (BucketArcProgressBar) ((a0) learnCheckpointFragment.J()).e.d;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsBucketProgressBar2, "assistantCheckpointDetailsBucketProgressBar");
                        float f2 = 100 - f;
                        Context contextRequireContext2 = learnCheckpointFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        assistantCheckpointDetailsBucketProgressBar2.a(f2, com.quizlet.themes.extensions.a.a(contextRequireContext2, R.attr.iconColorPrimaryInverse));
                        return Unit.a;
                    case 1:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.l lVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.l) obj;
                        String str2 = LearnCheckpointFragment.o;
                        if (lVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.j) {
                            List list = ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.j) lVar).a;
                            C4755a c4755a = learnCheckpointFragment.n;
                            if (c4755a == null) {
                                Intrinsics.m("adapter");
                                throw null;
                            }
                            c4755a.f(list);
                            learnCheckpointFragment.V(list.isEmpty());
                        }
                        return Unit.a;
                    case 2:
                        ((G) learnCheckpointFragment.m.getValue()).T();
                        return Unit.a;
                    default:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m mVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m) obj;
                        String str3 = LearnCheckpointFragment.o;
                        if (!(mVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        String str4 = mVar.a;
                        if (learnCheckpointFragment.isAdded() && learnCheckpointFragment.getFragmentManager() != null) {
                            String str5 = ImageOverlayDialogFragment.x;
                            AbstractC1136h0 abstractC1136h0RequireFragmentManager = learnCheckpointFragment.requireFragmentManager();
                            Intrinsics.checkNotNullExpressionValue(abstractC1136h0RequireFragmentManager, "requireFragmentManager(...)");
                            com.quizlet.quizletandroid.managers.upgrade.a.i(str4, abstractC1136h0RequireFragmentManager, null);
                        }
                        return Unit.a;
                }
            }
        }));
        final int i4 = 3;
        T().g.f(this, new com.quizlet.explanations.feedback.ui.fragments.c(20, new Function1(this) { // from class: com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.f
            public final /* synthetic */ LearnCheckpointFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) throws Resources.NotFoundException {
                LearnCheckpointFragment learnCheckpointFragment = this.b;
                switch (i4) {
                    case 0:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.a aVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.a) obj;
                        String str = LearnCheckpointFragment.o;
                        Intrinsics.d(aVar);
                        int i22 = aVar.a;
                        String strD = AbstractC3691o6.d(i22);
                        AppCompatTextView assistantCheckpointEmoji = (AppCompatTextView) ((a0) learnCheckpointFragment.J()).e.g;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointEmoji, "assistantCheckpointEmoji");
                        assistantCheckpointEmoji.setText(strD);
                        String string = learnCheckpointFragment.getString(AbstractC3691o6.e(i22));
                        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
                        QTextView assistantCheckpointMessage = (QTextView) ((a0) learnCheckpointFragment.J()).e.h;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointMessage, "assistantCheckpointMessage");
                        assistantCheckpointMessage.setText(string);
                        String string2 = learnCheckpointFragment.requireContext().getString(R.string.assistant_checkpoint_details_mastery_text_formatter, Integer.valueOf(i22));
                        Intrinsics.checkNotNullExpressionValue(string2, "getString(...)");
                        QTextView assistantCheckpointDetailsMasteryProgressText = (QTextView) ((a0) learnCheckpointFragment.J()).e.e;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsMasteryProgressText, "assistantCheckpointDetailsMasteryProgressText");
                        assistantCheckpointDetailsMasteryProgressText.setText(string2);
                        String string3 = learnCheckpointFragment.getString(R.string.new_assistant_checkpoint_details_mastery_text_cd, Integer.valueOf(i22));
                        Intrinsics.checkNotNullExpressionValue(string3, "getString(...)");
                        RelativeLayout assistantCheckpointDetailsMasteryParent = (RelativeLayout) ((a0) learnCheckpointFragment.J()).e.b;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsMasteryParent, "assistantCheckpointDetailsMasteryParent");
                        assistantCheckpointDetailsMasteryParent.setContentDescription(string3);
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.n nVar = aVar.b;
                        SegmentedBucketLayout2 assistantCheckpointDetailsNewBucketView = (SegmentedBucketLayout2) ((a0) learnCheckpointFragment.J()).e.f;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsNewBucketView, "assistantCheckpointDetailsNewBucketView");
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o.a;
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar2 = nVar.b;
                        assistantCheckpointDetailsNewBucketView.a(R.plurals.assistant_checkpoint_details_bucket_term, R.plurals.assistant_checkpoint_details_bucket_term_cd, R.attr.iconColorSecondary, nVar.c, oVar2 == oVar, new g(learnCheckpointFragment, 1), oVar);
                        SegmentedBucketLayout2 assistantCheckpointDetailsNewBucketView2 = (SegmentedBucketLayout2) ((a0) learnCheckpointFragment.J()).e.f;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsNewBucketView2, "assistantCheckpointDetailsNewBucketView");
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o oVar3 = com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.o.b;
                        assistantCheckpointDetailsNewBucketView2.a(R.plurals.assistant_checkpoint_details_bucket_familiar, R.plurals.assistant_checkpoint_details_bucket_familiar_cd, R.attr.iconColorSuccess, nVar.d, oVar2 == oVar3, new g(learnCheckpointFragment, 2), oVar3);
                        BucketArcProgressBar assistantCheckpointDetailsBucketProgressBar = (BucketArcProgressBar) ((a0) learnCheckpointFragment.J()).e.d;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsBucketProgressBar, "assistantCheckpointDetailsBucketProgressBar");
                        float f = nVar.a;
                        Context contextRequireContext = learnCheckpointFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext, "requireContext(...)");
                        assistantCheckpointDetailsBucketProgressBar.a(f, com.quizlet.themes.extensions.a.a(contextRequireContext, R.attr.colorProgressBar));
                        BucketArcProgressBar assistantCheckpointDetailsBucketProgressBar2 = (BucketArcProgressBar) ((a0) learnCheckpointFragment.J()).e.d;
                        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsBucketProgressBar2, "assistantCheckpointDetailsBucketProgressBar");
                        float f2 = 100 - f;
                        Context contextRequireContext2 = learnCheckpointFragment.requireContext();
                        Intrinsics.checkNotNullExpressionValue(contextRequireContext2, "requireContext(...)");
                        assistantCheckpointDetailsBucketProgressBar2.a(f2, com.quizlet.themes.extensions.a.a(contextRequireContext2, R.attr.iconColorPrimaryInverse));
                        return Unit.a;
                    case 1:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.l lVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.l) obj;
                        String str2 = LearnCheckpointFragment.o;
                        if (lVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.j) {
                            List list = ((com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.j) lVar).a;
                            C4755a c4755a = learnCheckpointFragment.n;
                            if (c4755a == null) {
                                Intrinsics.m("adapter");
                                throw null;
                            }
                            c4755a.f(list);
                            learnCheckpointFragment.V(list.isEmpty());
                        }
                        return Unit.a;
                    case 2:
                        ((G) learnCheckpointFragment.m.getValue()).T();
                        return Unit.a;
                    default:
                        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m mVar = (com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m) obj;
                        String str3 = LearnCheckpointFragment.o;
                        if (!(mVar instanceof com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.m)) {
                            throw new NoWhenBranchMatchedException();
                        }
                        String str4 = mVar.a;
                        if (learnCheckpointFragment.isAdded() && learnCheckpointFragment.getFragmentManager() != null) {
                            String str5 = ImageOverlayDialogFragment.x;
                            AbstractC1136h0 abstractC1136h0RequireFragmentManager = learnCheckpointFragment.requireFragmentManager();
                            Intrinsics.checkNotNullExpressionValue(abstractC1136h0RequireFragmentManager, "requireFragmentManager(...)");
                            com.quizlet.quizletandroid.managers.upgrade.a.i(str4, abstractC1136h0RequireFragmentManager, null);
                        }
                        return Unit.a;
                }
            }
        }));
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.viewmodel.d dVarT = T();
        com.quizlet.qutils.image.loading.a aVar = this.j;
        if (aVar == null) {
            Intrinsics.m("imageLoader");
            throw null;
        }
        com.quizlet.quizletandroid.managers.audio.h hVar = this.k;
        if (hVar == null) {
            Intrinsics.m("audioManager");
            throw null;
        }
        this.n = new C4755a(dVarT, aVar, hVar);
        RecyclerView assistantCheckpointDetailsTermListRecyclerView = ((a0) J()).d;
        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsTermListRecyclerView, "assistantCheckpointDetailsTermListRecyclerView");
        assistantCheckpointDetailsTermListRecyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        RecyclerView assistantCheckpointDetailsTermListRecyclerView2 = ((a0) J()).d;
        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsTermListRecyclerView2, "assistantCheckpointDetailsTermListRecyclerView");
        assistantCheckpointDetailsTermListRecyclerView2.setItemAnimator(null);
        RecyclerView assistantCheckpointDetailsTermListRecyclerView3 = ((a0) J()).d;
        Intrinsics.checkNotNullExpressionValue(assistantCheckpointDetailsTermListRecyclerView3, "assistantCheckpointDetailsTermListRecyclerView");
        C4755a c4755a = this.n;
        if (c4755a == null) {
            Intrinsics.m("adapter");
            throw null;
        }
        assistantCheckpointDetailsTermListRecyclerView3.setAdapter(c4755a);
        QButton assistantCheckpointContinueButton = ((a0) J()).c;
        Intrinsics.checkNotNullExpressionValue(assistantCheckpointContinueButton, "assistantCheckpointContinueButton");
        assistantCheckpointContinueButton.setOnClickListener(new g(this, 0));
    }
}
