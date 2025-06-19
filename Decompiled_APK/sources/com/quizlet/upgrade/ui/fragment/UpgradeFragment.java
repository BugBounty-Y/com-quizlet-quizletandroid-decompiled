package com.quizlet.upgrade.ui.fragment;

import android.content.res.Resources;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.Toast;
import androidx.compose.ui.node.B;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.constraintlayout.widget.Group;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.fragment.app.AbstractC1136h0;
import androidx.fragment.app.C1121a;
import androidx.fragment.app.I;
import androidx.lifecycle.C;
import androidx.lifecycle.X;
import androidx.lifecycle.Y;
import androidx.lifecycle.m0;
import androidx.lifecycle.p0;
import androidx.recyclerview.widget.AbstractC1361d0;
import androidx.recyclerview.widget.C1370i;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.google.android.material.appbar.AppBarLayout;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblyTextButton;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.t;
import com.quizlet.uicommon.ui.common.views.QuizletPlusLogo;
import com.quizlet.upgrade.data.UpgradePackage;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.u;
import kotlinx.coroutines.E;

@Metadata
/* loaded from: classes3.dex */
public final class UpgradeFragment extends Hilt_UpgradeFragment<com.quizlet.upgrade.databinding.c> {
    public static final String r;
    public com.quizlet.billing.subscriptions.h j;
    public com.quizlet.quizletandroid.ui.navigationmanagers.i k;
    public com.quizlet.quizletandroid.ui.webpages.a l;
    public final com.quizlet.explanations.myexplanations.ui.recyclerview.b m = new com.quizlet.explanations.myexplanations.ui.recyclerview.b(AbstractC4178x.h("diffUtilCallback"), 6);
    public final com.quizlet.explanations.solution.recyclerview.step.l n = new com.quizlet.explanations.solution.recyclerview.step.l();
    public final com.quizlet.data.repository.folderwithcreatorinclass.e o;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e p;
    public final u q;

    static {
        Intrinsics.checkNotNullExpressionValue("UpgradeFragment", "getSimpleName(...)");
        r = "UpgradeFragment";
    }

    public UpgradeFragment() {
        h hVar = new h(this, 0);
        kotlin.m mVar = kotlin.m.c;
        kotlin.k kVarA = kotlin.l.a(mVar, new t(hVar, 10));
        this.o = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.upgrade.viewmodel.n.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 17), new g(this, kVarA, 1), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 18));
        kotlin.k kVarA2 = kotlin.l.a(mVar, new t(new h(this, 1), 11));
        this.p = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.upgrade.viewmodel.h.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA2, 19), new g(this, kVarA2, 0), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA2, 20));
        this.q = kotlin.l.b(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 14));
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final String N() {
        return r;
    }

    @Override // com.quizlet.baseui.base.BaseFragment
    public final androidx.viewbinding.a O(LayoutInflater inflater, ViewGroup viewGroup) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = getLayoutInflater().inflate(R.layout.fragment_upgrade_v2, viewGroup, false);
        int i = R.id.appBarLayout;
        if (((AppBarLayout) AbstractC3375o2.c(R.id.appBarLayout, viewInflate)) != null) {
            i = R.id.ctaButtons;
            View viewC = AbstractC3375o2.c(R.id.ctaButtons, viewInflate);
            if (viewC != null) {
                int i2 = R.id.continueFreeButton;
                AssemblyTextButton assemblyTextButton = (AssemblyTextButton) AbstractC3375o2.c(R.id.continueFreeButton, viewC);
                if (assemblyTextButton != null) {
                    i2 = R.id.freeTrialText;
                    QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.freeTrialText, viewC);
                    if (qTextView != null) {
                        i2 = R.id.seePlansButton;
                        AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.seePlansButton, viewC);
                        if (assemblyPrimaryButton != null) {
                            com.quizlet.features.infra.legacyadapter.databinding.f fVar = new com.quizlet.features.infra.legacyadapter.databinding.f((ConstraintLayout) viewC, (Object) assemblyTextButton, (View) qTextView, (Object) assemblyPrimaryButton, 13);
                            i = R.id.divider;
                            View viewC2 = AbstractC3375o2.c(R.id.divider, viewInflate);
                            if (viewC2 != null) {
                                i = R.id.features;
                                if (((CoordinatorLayout) AbstractC3375o2.c(R.id.features, viewInflate)) != null) {
                                    i = R.id.loadingProgress;
                                    ProgressBar progressBar = (ProgressBar) AbstractC3375o2.c(R.id.loadingProgress, viewInflate);
                                    if (progressBar != null) {
                                        i = R.id.recyclerView;
                                        RecyclerView recyclerView = (RecyclerView) AbstractC3375o2.c(R.id.recyclerView, viewInflate);
                                        if (recyclerView != null) {
                                            i = R.id.upgradeHeader;
                                            View viewC3 = AbstractC3375o2.c(R.id.upgradeHeader, viewInflate);
                                            if (viewC3 != null) {
                                                int i3 = R.id.bulletBackgroundGradient;
                                                View viewC4 = AbstractC3375o2.c(R.id.bulletBackgroundGradient, viewC3);
                                                if (viewC4 != null) {
                                                    i3 = R.id.endBullet;
                                                    View viewC5 = AbstractC3375o2.c(R.id.endBullet, viewC3);
                                                    if (viewC5 != null) {
                                                        i3 = R.id.endBulletHeader;
                                                        QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.endBulletHeader, viewC3);
                                                        if (qTextView2 != null) {
                                                            i3 = R.id.endBulletInfo;
                                                            QTextView qTextView3 = (QTextView) AbstractC3375o2.c(R.id.endBulletInfo, viewC3);
                                                            if (qTextView3 != null) {
                                                                i3 = R.id.freeTrialHeader;
                                                                QTextView qTextView4 = (QTextView) AbstractC3375o2.c(R.id.freeTrialHeader, viewC3);
                                                                if (qTextView4 != null) {
                                                                    i3 = R.id.freeTrialViews;
                                                                    Group group = (Group) AbstractC3375o2.c(R.id.freeTrialViews, viewC3);
                                                                    if (group != null) {
                                                                        i3 = R.id.header_annual_cost;
                                                                        QTextView qTextView5 = (QTextView) AbstractC3375o2.c(R.id.header_annual_cost, viewC3);
                                                                        if (qTextView5 != null) {
                                                                            i3 = R.id.header_annual_monthly_cost;
                                                                            QTextView qTextView6 = (QTextView) AbstractC3375o2.c(R.id.header_annual_monthly_cost, viewC3);
                                                                            if (qTextView6 != null) {
                                                                                i3 = R.id.header_annual_monthly_cost_underline;
                                                                                if (((ImageView) AbstractC3375o2.c(R.id.header_annual_monthly_cost_underline, viewC3)) != null) {
                                                                                    i3 = R.id.header_cost;
                                                                                    if (((LinearLayout) AbstractC3375o2.c(R.id.header_cost, viewC3)) != null) {
                                                                                        i3 = R.id.headerCostViews;
                                                                                        Group group2 = (Group) AbstractC3375o2.c(R.id.headerCostViews, viewC3);
                                                                                        if (group2 != null) {
                                                                                            i3 = R.id.header_current_sub_description;
                                                                                            QTextView qTextView7 = (QTextView) AbstractC3375o2.c(R.id.header_current_sub_description, viewC3);
                                                                                            if (qTextView7 != null) {
                                                                                                i3 = R.id.header_manage_subscription_link;
                                                                                                QTextView qTextView8 = (QTextView) AbstractC3375o2.c(R.id.header_manage_subscription_link, viewC3);
                                                                                                if (qTextView8 != null) {
                                                                                                    i3 = R.id.header_subscription_period;
                                                                                                    QTextView qTextView9 = (QTextView) AbstractC3375o2.c(R.id.header_subscription_period, viewC3);
                                                                                                    if (qTextView9 != null) {
                                                                                                        i3 = R.id.headerTitleText;
                                                                                                        QuizletPlusLogo quizletPlusLogo = (QuizletPlusLogo) AbstractC3375o2.c(R.id.headerTitleText, viewC3);
                                                                                                        if (quizletPlusLogo != null) {
                                                                                                            i3 = R.id.todayBullet;
                                                                                                            View viewC6 = AbstractC3375o2.c(R.id.todayBullet, viewC3);
                                                                                                            if (viewC6 != null) {
                                                                                                                i3 = R.id.todayBulletHeader;
                                                                                                                if (((QTextView) AbstractC3375o2.c(R.id.todayBulletHeader, viewC3)) != null) {
                                                                                                                    i3 = R.id.todayBulletInfo;
                                                                                                                    QTextView qTextView10 = (QTextView) AbstractC3375o2.c(R.id.todayBulletInfo, viewC3);
                                                                                                                    if (qTextView10 != null) {
                                                                                                                        com.quizlet.upgrade.databinding.c cVar = new com.quizlet.upgrade.databinding.c((ConstraintLayout) viewInflate, fVar, viewC2, progressBar, recyclerView, new com.onetrust.otpublishers.headless.databinding.g((ConstraintLayout) viewC3, viewC4, viewC5, qTextView2, qTextView3, qTextView4, group, qTextView5, qTextView6, group2, qTextView7, qTextView8, qTextView9, quizletPlusLogo, viewC6, qTextView10));
                                                                                                                        Intrinsics.checkNotNullExpressionValue(cVar, "inflate(...)");
                                                                                                                        return cVar;
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                throw new NullPointerException("Missing required view with ID: ".concat(viewC3.getResources().getResourceName(i3)));
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
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    public final com.quizlet.upgrade.viewmodel.h T() {
        return (com.quizlet.upgrade.viewmodel.h) this.p.getValue();
    }

    public final com.quizlet.upgrade.viewmodel.n U() {
        return (com.quizlet.upgrade.viewmodel.n) this.o.getValue();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        com.quizlet.billing.subscriptions.h hVar = this.j;
        if (hVar == null) {
            Intrinsics.m("subscriptionHandler");
            throw null;
        }
        hVar.e = U();
        C lifecycle = getLifecycle();
        com.quizlet.billing.subscriptions.h hVar2 = this.j;
        if (hVar2 != null) {
            lifecycle.a(hVar2);
        } else {
            Intrinsics.m("subscriptionHandler");
            throw null;
        }
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        ((com.quizlet.upgrade.databinding.c) J()).e.setAdapter(null);
        super.onDestroyView();
    }

    @Override // com.quizlet.baseui.base.BaseFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        if (((Boolean) this.q.getValue()).booleanValue()) {
            ConstraintLayout constraintLayout = (ConstraintLayout) ((com.quizlet.upgrade.databinding.c) J()).f.c;
            Intrinsics.checkNotNullExpressionValue(constraintLayout, "getRoot(...)");
            constraintLayout.setPadding(constraintLayout.getPaddingLeft(), getResources().getDimensionPixelSize(R.dimen.ref_spacing_medium), constraintLayout.getPaddingRight(), constraintLayout.getPaddingBottom());
        }
        final int i = 0;
        ((Y) U().d.e).f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new Function1(this) { // from class: com.quizlet.upgrade.ui.fragment.f
            public final /* synthetic */ UpgradeFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UpgradeFragment upgradeFragment = this.b;
                switch (i) {
                    case 0:
                        com.quizlet.upgrade.manager.i iVar = (com.quizlet.upgrade.manager.i) obj;
                        String str = UpgradeFragment.r;
                        boolean z = iVar instanceof com.quizlet.upgrade.manager.g;
                        ProgressBar loadingProgress = ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).d;
                        Intrinsics.checkNotNullExpressionValue(loadingProgress, "loadingProgress");
                        loadingProgress.setVisibility(z ? 0 : 8);
                        if (!Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.b) && !Intrinsics.b(iVar, com.quizlet.upgrade.manager.g.a)) {
                            if (Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.a)) {
                                a aVar = new a();
                                I activity = upgradeFragment.requireActivity();
                                Intrinsics.checkNotNullExpressionValue(activity, "requireActivity(...)");
                                Intrinsics.checkNotNullParameter(activity, "activity");
                                AbstractC1136h0 supportFragmentManager = activity.getSupportFragmentManager();
                                aVar.n = false;
                                aVar.o = true;
                                C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                                c1121aB.p = true;
                                c1121aB.i(0, aVar, "BillingErrorAlertDialog", 1);
                                if (c1121aB.g) {
                                    throw new IllegalStateException("This transaction is already being added to the back stack");
                                }
                                c1121aB.h = false;
                                c1121aB.r.B(c1121aB, false);
                            } else {
                                if (!(iVar instanceof com.quizlet.upgrade.manager.h)) {
                                    throw new NoWhenBranchMatchedException();
                                }
                                UpgradePackage upgradePackage = ((com.quizlet.upgrade.manager.h) iVar).a;
                                Bundle bundle2 = new Bundle(0);
                                bundle2.putInt("ResultUserUpgradeType", upgradePackage.b);
                                upgradeFragment.getParentFragmentManager().g0(bundle2, "UpgradeFragmentRequestKey");
                            }
                        }
                        return Unit.a;
                    case 1:
                        com.quizlet.upgrade.manager.d dVar = (com.quizlet.upgrade.manager.d) obj;
                        String str2 = UpgradeFragment.r;
                        if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.c.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_failed_to_upgrade, 1).show();
                        } else if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.a.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_unavailable_logged_out, 1).show();
                        } else {
                            if (!(dVar instanceof com.quizlet.upgrade.manager.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.upgrade.data.I i2 = ((com.quizlet.upgrade.manager.b) dVar).a;
                            com.quizlet.billing.subscriptions.h hVar = upgradeFragment.j;
                            if (hVar == null) {
                                Intrinsics.m("subscriptionHandler");
                                throw null;
                            }
                            I iRequireActivity = upgradeFragment.requireActivity();
                            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
                            com.quizlet.billing.subscriptions.j jVar = i2.a;
                            if (hVar.e == null) {
                                throw new IllegalStateException("onPurchaseCompleteListener is not initialized. Call setOnPurchaseCompleteListener() before checkout (launchPurchase()).");
                            }
                            com.quizlet.billing.model.b bVarE = hVar.b.e();
                            io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, hVar.i.f.e(new com.quizlet.billing.subscriptions.f(hVar, 2)), new com.google.firebase.tracing.a(6, hVar, jVar));
                            long j = bVarE.a;
                            String str3 = i2.b;
                            hVar.a(new io.reactivex.rxjava3.internal.operators.maybe.h(1, hVar2, new com.quizlet.billing.subscriptions.g(hVar, iRequireActivity, j, jVar, str3)).h(), j, str3);
                        }
                        return Unit.a;
                    case 2:
                        String str4 = UpgradeFragment.r;
                        a aVar2 = new a();
                        I activity2 = upgradeFragment.requireActivity();
                        Intrinsics.checkNotNullExpressionValue(activity2, "requireActivity(...)");
                        Intrinsics.checkNotNullParameter(activity2, "activity");
                        AbstractC1136h0 supportFragmentManager2 = activity2.getSupportFragmentManager();
                        aVar2.n = false;
                        aVar2.o = true;
                        C1121a c1121aB2 = B.b(supportFragmentManager2, supportFragmentManager2);
                        c1121aB2.p = true;
                        c1121aB2.i(0, aVar2, "BillingErrorAlertDialog", 1);
                        if (c1121aB2.g) {
                            throw new IllegalStateException("This transaction is already being added to the back stack");
                        }
                        c1121aB2.h = false;
                        c1121aB2.r.B(c1121aB2, false);
                        return Unit.a;
                    case 3:
                        String str5 = UpgradeFragment.r;
                        ((QuizletPlusLogo) ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).f.o).setLogoVariant((com.quizlet.ui.states.a) obj);
                        return Unit.a;
                    case 4:
                        String str6 = UpgradeFragment.r;
                        new TermsAndConditionsModalFragment().O(upgradeFragment.getChildFragmentManager(), TermsAndConditionsModalFragment.V);
                        return Unit.a;
                    case 5:
                        com.quizlet.upgrade.data.C c = (com.quizlet.upgrade.data.C) obj;
                        upgradeFragment.m.f(c.a);
                        upgradeFragment.n.f(c.b);
                        com.quizlet.upgrade.viewmodel.h hVarT = upgradeFragment.T();
                        m0 m0Var = hVarT.c;
                        Boolean bool = (Boolean) m0Var.a("skipToPlansState");
                        if (bool != null ? bool.booleanValue() : false) {
                            m0Var.c(Boolean.FALSE, "skipToPlansState");
                            E.A(p0.j(hVarT), null, null, new com.quizlet.upgrade.viewmodel.e(hVarT, null), 3);
                        }
                        return Unit.a;
                    case 6:
                        String str7 = UpgradeFragment.r;
                        new UpgradePlansModalFragment().O(upgradeFragment.getChildFragmentManager(), UpgradePlansModalFragment.W);
                        return Unit.a;
                    default:
                        String str8 = UpgradeFragment.r;
                        Y y = upgradeFragment.U().h;
                        Unit unit = Unit.a;
                        y.j(unit);
                        return unit;
                }
            }
        }));
        final int i2 = 1;
        ((X) U().d.f).f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new Function1(this) { // from class: com.quizlet.upgrade.ui.fragment.f
            public final /* synthetic */ UpgradeFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UpgradeFragment upgradeFragment = this.b;
                switch (i2) {
                    case 0:
                        com.quizlet.upgrade.manager.i iVar = (com.quizlet.upgrade.manager.i) obj;
                        String str = UpgradeFragment.r;
                        boolean z = iVar instanceof com.quizlet.upgrade.manager.g;
                        ProgressBar loadingProgress = ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).d;
                        Intrinsics.checkNotNullExpressionValue(loadingProgress, "loadingProgress");
                        loadingProgress.setVisibility(z ? 0 : 8);
                        if (!Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.b) && !Intrinsics.b(iVar, com.quizlet.upgrade.manager.g.a)) {
                            if (Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.a)) {
                                a aVar = new a();
                                I activity = upgradeFragment.requireActivity();
                                Intrinsics.checkNotNullExpressionValue(activity, "requireActivity(...)");
                                Intrinsics.checkNotNullParameter(activity, "activity");
                                AbstractC1136h0 supportFragmentManager = activity.getSupportFragmentManager();
                                aVar.n = false;
                                aVar.o = true;
                                C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                                c1121aB.p = true;
                                c1121aB.i(0, aVar, "BillingErrorAlertDialog", 1);
                                if (c1121aB.g) {
                                    throw new IllegalStateException("This transaction is already being added to the back stack");
                                }
                                c1121aB.h = false;
                                c1121aB.r.B(c1121aB, false);
                            } else {
                                if (!(iVar instanceof com.quizlet.upgrade.manager.h)) {
                                    throw new NoWhenBranchMatchedException();
                                }
                                UpgradePackage upgradePackage = ((com.quizlet.upgrade.manager.h) iVar).a;
                                Bundle bundle2 = new Bundle(0);
                                bundle2.putInt("ResultUserUpgradeType", upgradePackage.b);
                                upgradeFragment.getParentFragmentManager().g0(bundle2, "UpgradeFragmentRequestKey");
                            }
                        }
                        return Unit.a;
                    case 1:
                        com.quizlet.upgrade.manager.d dVar = (com.quizlet.upgrade.manager.d) obj;
                        String str2 = UpgradeFragment.r;
                        if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.c.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_failed_to_upgrade, 1).show();
                        } else if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.a.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_unavailable_logged_out, 1).show();
                        } else {
                            if (!(dVar instanceof com.quizlet.upgrade.manager.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.upgrade.data.I i22 = ((com.quizlet.upgrade.manager.b) dVar).a;
                            com.quizlet.billing.subscriptions.h hVar = upgradeFragment.j;
                            if (hVar == null) {
                                Intrinsics.m("subscriptionHandler");
                                throw null;
                            }
                            I iRequireActivity = upgradeFragment.requireActivity();
                            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
                            com.quizlet.billing.subscriptions.j jVar = i22.a;
                            if (hVar.e == null) {
                                throw new IllegalStateException("onPurchaseCompleteListener is not initialized. Call setOnPurchaseCompleteListener() before checkout (launchPurchase()).");
                            }
                            com.quizlet.billing.model.b bVarE = hVar.b.e();
                            io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, hVar.i.f.e(new com.quizlet.billing.subscriptions.f(hVar, 2)), new com.google.firebase.tracing.a(6, hVar, jVar));
                            long j = bVarE.a;
                            String str3 = i22.b;
                            hVar.a(new io.reactivex.rxjava3.internal.operators.maybe.h(1, hVar2, new com.quizlet.billing.subscriptions.g(hVar, iRequireActivity, j, jVar, str3)).h(), j, str3);
                        }
                        return Unit.a;
                    case 2:
                        String str4 = UpgradeFragment.r;
                        a aVar2 = new a();
                        I activity2 = upgradeFragment.requireActivity();
                        Intrinsics.checkNotNullExpressionValue(activity2, "requireActivity(...)");
                        Intrinsics.checkNotNullParameter(activity2, "activity");
                        AbstractC1136h0 supportFragmentManager2 = activity2.getSupportFragmentManager();
                        aVar2.n = false;
                        aVar2.o = true;
                        C1121a c1121aB2 = B.b(supportFragmentManager2, supportFragmentManager2);
                        c1121aB2.p = true;
                        c1121aB2.i(0, aVar2, "BillingErrorAlertDialog", 1);
                        if (c1121aB2.g) {
                            throw new IllegalStateException("This transaction is already being added to the back stack");
                        }
                        c1121aB2.h = false;
                        c1121aB2.r.B(c1121aB2, false);
                        return Unit.a;
                    case 3:
                        String str5 = UpgradeFragment.r;
                        ((QuizletPlusLogo) ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).f.o).setLogoVariant((com.quizlet.ui.states.a) obj);
                        return Unit.a;
                    case 4:
                        String str6 = UpgradeFragment.r;
                        new TermsAndConditionsModalFragment().O(upgradeFragment.getChildFragmentManager(), TermsAndConditionsModalFragment.V);
                        return Unit.a;
                    case 5:
                        com.quizlet.upgrade.data.C c = (com.quizlet.upgrade.data.C) obj;
                        upgradeFragment.m.f(c.a);
                        upgradeFragment.n.f(c.b);
                        com.quizlet.upgrade.viewmodel.h hVarT = upgradeFragment.T();
                        m0 m0Var = hVarT.c;
                        Boolean bool = (Boolean) m0Var.a("skipToPlansState");
                        if (bool != null ? bool.booleanValue() : false) {
                            m0Var.c(Boolean.FALSE, "skipToPlansState");
                            E.A(p0.j(hVarT), null, null, new com.quizlet.upgrade.viewmodel.e(hVarT, null), 3);
                        }
                        return Unit.a;
                    case 6:
                        String str7 = UpgradeFragment.r;
                        new UpgradePlansModalFragment().O(upgradeFragment.getChildFragmentManager(), UpgradePlansModalFragment.W);
                        return Unit.a;
                    default:
                        String str8 = UpgradeFragment.r;
                        Y y = upgradeFragment.U().h;
                        Unit unit = Unit.a;
                        y.j(unit);
                        return unit;
                }
            }
        }));
        U().f.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new com.quizlet.search.composables.E(1, this, UpgradeFragment.class, "onDismiss", "onDismiss(Lcom/quizlet/upgrade/data/UpgradeDismissEvent;)V", 0, 5)));
        final int i3 = 2;
        U().h.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new Function1(this) { // from class: com.quizlet.upgrade.ui.fragment.f
            public final /* synthetic */ UpgradeFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UpgradeFragment upgradeFragment = this.b;
                switch (i3) {
                    case 0:
                        com.quizlet.upgrade.manager.i iVar = (com.quizlet.upgrade.manager.i) obj;
                        String str = UpgradeFragment.r;
                        boolean z = iVar instanceof com.quizlet.upgrade.manager.g;
                        ProgressBar loadingProgress = ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).d;
                        Intrinsics.checkNotNullExpressionValue(loadingProgress, "loadingProgress");
                        loadingProgress.setVisibility(z ? 0 : 8);
                        if (!Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.b) && !Intrinsics.b(iVar, com.quizlet.upgrade.manager.g.a)) {
                            if (Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.a)) {
                                a aVar = new a();
                                I activity = upgradeFragment.requireActivity();
                                Intrinsics.checkNotNullExpressionValue(activity, "requireActivity(...)");
                                Intrinsics.checkNotNullParameter(activity, "activity");
                                AbstractC1136h0 supportFragmentManager = activity.getSupportFragmentManager();
                                aVar.n = false;
                                aVar.o = true;
                                C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                                c1121aB.p = true;
                                c1121aB.i(0, aVar, "BillingErrorAlertDialog", 1);
                                if (c1121aB.g) {
                                    throw new IllegalStateException("This transaction is already being added to the back stack");
                                }
                                c1121aB.h = false;
                                c1121aB.r.B(c1121aB, false);
                            } else {
                                if (!(iVar instanceof com.quizlet.upgrade.manager.h)) {
                                    throw new NoWhenBranchMatchedException();
                                }
                                UpgradePackage upgradePackage = ((com.quizlet.upgrade.manager.h) iVar).a;
                                Bundle bundle2 = new Bundle(0);
                                bundle2.putInt("ResultUserUpgradeType", upgradePackage.b);
                                upgradeFragment.getParentFragmentManager().g0(bundle2, "UpgradeFragmentRequestKey");
                            }
                        }
                        return Unit.a;
                    case 1:
                        com.quizlet.upgrade.manager.d dVar = (com.quizlet.upgrade.manager.d) obj;
                        String str2 = UpgradeFragment.r;
                        if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.c.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_failed_to_upgrade, 1).show();
                        } else if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.a.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_unavailable_logged_out, 1).show();
                        } else {
                            if (!(dVar instanceof com.quizlet.upgrade.manager.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.upgrade.data.I i22 = ((com.quizlet.upgrade.manager.b) dVar).a;
                            com.quizlet.billing.subscriptions.h hVar = upgradeFragment.j;
                            if (hVar == null) {
                                Intrinsics.m("subscriptionHandler");
                                throw null;
                            }
                            I iRequireActivity = upgradeFragment.requireActivity();
                            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
                            com.quizlet.billing.subscriptions.j jVar = i22.a;
                            if (hVar.e == null) {
                                throw new IllegalStateException("onPurchaseCompleteListener is not initialized. Call setOnPurchaseCompleteListener() before checkout (launchPurchase()).");
                            }
                            com.quizlet.billing.model.b bVarE = hVar.b.e();
                            io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, hVar.i.f.e(new com.quizlet.billing.subscriptions.f(hVar, 2)), new com.google.firebase.tracing.a(6, hVar, jVar));
                            long j = bVarE.a;
                            String str3 = i22.b;
                            hVar.a(new io.reactivex.rxjava3.internal.operators.maybe.h(1, hVar2, new com.quizlet.billing.subscriptions.g(hVar, iRequireActivity, j, jVar, str3)).h(), j, str3);
                        }
                        return Unit.a;
                    case 2:
                        String str4 = UpgradeFragment.r;
                        a aVar2 = new a();
                        I activity2 = upgradeFragment.requireActivity();
                        Intrinsics.checkNotNullExpressionValue(activity2, "requireActivity(...)");
                        Intrinsics.checkNotNullParameter(activity2, "activity");
                        AbstractC1136h0 supportFragmentManager2 = activity2.getSupportFragmentManager();
                        aVar2.n = false;
                        aVar2.o = true;
                        C1121a c1121aB2 = B.b(supportFragmentManager2, supportFragmentManager2);
                        c1121aB2.p = true;
                        c1121aB2.i(0, aVar2, "BillingErrorAlertDialog", 1);
                        if (c1121aB2.g) {
                            throw new IllegalStateException("This transaction is already being added to the back stack");
                        }
                        c1121aB2.h = false;
                        c1121aB2.r.B(c1121aB2, false);
                        return Unit.a;
                    case 3:
                        String str5 = UpgradeFragment.r;
                        ((QuizletPlusLogo) ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).f.o).setLogoVariant((com.quizlet.ui.states.a) obj);
                        return Unit.a;
                    case 4:
                        String str6 = UpgradeFragment.r;
                        new TermsAndConditionsModalFragment().O(upgradeFragment.getChildFragmentManager(), TermsAndConditionsModalFragment.V);
                        return Unit.a;
                    case 5:
                        com.quizlet.upgrade.data.C c = (com.quizlet.upgrade.data.C) obj;
                        upgradeFragment.m.f(c.a);
                        upgradeFragment.n.f(c.b);
                        com.quizlet.upgrade.viewmodel.h hVarT = upgradeFragment.T();
                        m0 m0Var = hVarT.c;
                        Boolean bool = (Boolean) m0Var.a("skipToPlansState");
                        if (bool != null ? bool.booleanValue() : false) {
                            m0Var.c(Boolean.FALSE, "skipToPlansState");
                            E.A(p0.j(hVarT), null, null, new com.quizlet.upgrade.viewmodel.e(hVarT, null), 3);
                        }
                        return Unit.a;
                    case 6:
                        String str7 = UpgradeFragment.r;
                        new UpgradePlansModalFragment().O(upgradeFragment.getChildFragmentManager(), UpgradePlansModalFragment.W);
                        return Unit.a;
                    default:
                        String str8 = UpgradeFragment.r;
                        Y y = upgradeFragment.U().h;
                        Unit unit = Unit.a;
                        y.j(unit);
                        return unit;
                }
            }
        }));
        final int i4 = 3;
        U().e.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new Function1(this) { // from class: com.quizlet.upgrade.ui.fragment.f
            public final /* synthetic */ UpgradeFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UpgradeFragment upgradeFragment = this.b;
                switch (i4) {
                    case 0:
                        com.quizlet.upgrade.manager.i iVar = (com.quizlet.upgrade.manager.i) obj;
                        String str = UpgradeFragment.r;
                        boolean z = iVar instanceof com.quizlet.upgrade.manager.g;
                        ProgressBar loadingProgress = ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).d;
                        Intrinsics.checkNotNullExpressionValue(loadingProgress, "loadingProgress");
                        loadingProgress.setVisibility(z ? 0 : 8);
                        if (!Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.b) && !Intrinsics.b(iVar, com.quizlet.upgrade.manager.g.a)) {
                            if (Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.a)) {
                                a aVar = new a();
                                I activity = upgradeFragment.requireActivity();
                                Intrinsics.checkNotNullExpressionValue(activity, "requireActivity(...)");
                                Intrinsics.checkNotNullParameter(activity, "activity");
                                AbstractC1136h0 supportFragmentManager = activity.getSupportFragmentManager();
                                aVar.n = false;
                                aVar.o = true;
                                C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                                c1121aB.p = true;
                                c1121aB.i(0, aVar, "BillingErrorAlertDialog", 1);
                                if (c1121aB.g) {
                                    throw new IllegalStateException("This transaction is already being added to the back stack");
                                }
                                c1121aB.h = false;
                                c1121aB.r.B(c1121aB, false);
                            } else {
                                if (!(iVar instanceof com.quizlet.upgrade.manager.h)) {
                                    throw new NoWhenBranchMatchedException();
                                }
                                UpgradePackage upgradePackage = ((com.quizlet.upgrade.manager.h) iVar).a;
                                Bundle bundle2 = new Bundle(0);
                                bundle2.putInt("ResultUserUpgradeType", upgradePackage.b);
                                upgradeFragment.getParentFragmentManager().g0(bundle2, "UpgradeFragmentRequestKey");
                            }
                        }
                        return Unit.a;
                    case 1:
                        com.quizlet.upgrade.manager.d dVar = (com.quizlet.upgrade.manager.d) obj;
                        String str2 = UpgradeFragment.r;
                        if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.c.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_failed_to_upgrade, 1).show();
                        } else if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.a.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_unavailable_logged_out, 1).show();
                        } else {
                            if (!(dVar instanceof com.quizlet.upgrade.manager.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.upgrade.data.I i22 = ((com.quizlet.upgrade.manager.b) dVar).a;
                            com.quizlet.billing.subscriptions.h hVar = upgradeFragment.j;
                            if (hVar == null) {
                                Intrinsics.m("subscriptionHandler");
                                throw null;
                            }
                            I iRequireActivity = upgradeFragment.requireActivity();
                            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
                            com.quizlet.billing.subscriptions.j jVar = i22.a;
                            if (hVar.e == null) {
                                throw new IllegalStateException("onPurchaseCompleteListener is not initialized. Call setOnPurchaseCompleteListener() before checkout (launchPurchase()).");
                            }
                            com.quizlet.billing.model.b bVarE = hVar.b.e();
                            io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, hVar.i.f.e(new com.quizlet.billing.subscriptions.f(hVar, 2)), new com.google.firebase.tracing.a(6, hVar, jVar));
                            long j = bVarE.a;
                            String str3 = i22.b;
                            hVar.a(new io.reactivex.rxjava3.internal.operators.maybe.h(1, hVar2, new com.quizlet.billing.subscriptions.g(hVar, iRequireActivity, j, jVar, str3)).h(), j, str3);
                        }
                        return Unit.a;
                    case 2:
                        String str4 = UpgradeFragment.r;
                        a aVar2 = new a();
                        I activity2 = upgradeFragment.requireActivity();
                        Intrinsics.checkNotNullExpressionValue(activity2, "requireActivity(...)");
                        Intrinsics.checkNotNullParameter(activity2, "activity");
                        AbstractC1136h0 supportFragmentManager2 = activity2.getSupportFragmentManager();
                        aVar2.n = false;
                        aVar2.o = true;
                        C1121a c1121aB2 = B.b(supportFragmentManager2, supportFragmentManager2);
                        c1121aB2.p = true;
                        c1121aB2.i(0, aVar2, "BillingErrorAlertDialog", 1);
                        if (c1121aB2.g) {
                            throw new IllegalStateException("This transaction is already being added to the back stack");
                        }
                        c1121aB2.h = false;
                        c1121aB2.r.B(c1121aB2, false);
                        return Unit.a;
                    case 3:
                        String str5 = UpgradeFragment.r;
                        ((QuizletPlusLogo) ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).f.o).setLogoVariant((com.quizlet.ui.states.a) obj);
                        return Unit.a;
                    case 4:
                        String str6 = UpgradeFragment.r;
                        new TermsAndConditionsModalFragment().O(upgradeFragment.getChildFragmentManager(), TermsAndConditionsModalFragment.V);
                        return Unit.a;
                    case 5:
                        com.quizlet.upgrade.data.C c = (com.quizlet.upgrade.data.C) obj;
                        upgradeFragment.m.f(c.a);
                        upgradeFragment.n.f(c.b);
                        com.quizlet.upgrade.viewmodel.h hVarT = upgradeFragment.T();
                        m0 m0Var = hVarT.c;
                        Boolean bool = (Boolean) m0Var.a("skipToPlansState");
                        if (bool != null ? bool.booleanValue() : false) {
                            m0Var.c(Boolean.FALSE, "skipToPlansState");
                            E.A(p0.j(hVarT), null, null, new com.quizlet.upgrade.viewmodel.e(hVarT, null), 3);
                        }
                        return Unit.a;
                    case 6:
                        String str7 = UpgradeFragment.r;
                        new UpgradePlansModalFragment().O(upgradeFragment.getChildFragmentManager(), UpgradePlansModalFragment.W);
                        return Unit.a;
                    default:
                        String str8 = UpgradeFragment.r;
                        Y y = upgradeFragment.U().h;
                        Unit unit = Unit.a;
                        y.j(unit);
                        return unit;
                }
            }
        }));
        final int i5 = 4;
        U().g.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new Function1(this) { // from class: com.quizlet.upgrade.ui.fragment.f
            public final /* synthetic */ UpgradeFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UpgradeFragment upgradeFragment = this.b;
                switch (i5) {
                    case 0:
                        com.quizlet.upgrade.manager.i iVar = (com.quizlet.upgrade.manager.i) obj;
                        String str = UpgradeFragment.r;
                        boolean z = iVar instanceof com.quizlet.upgrade.manager.g;
                        ProgressBar loadingProgress = ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).d;
                        Intrinsics.checkNotNullExpressionValue(loadingProgress, "loadingProgress");
                        loadingProgress.setVisibility(z ? 0 : 8);
                        if (!Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.b) && !Intrinsics.b(iVar, com.quizlet.upgrade.manager.g.a)) {
                            if (Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.a)) {
                                a aVar = new a();
                                I activity = upgradeFragment.requireActivity();
                                Intrinsics.checkNotNullExpressionValue(activity, "requireActivity(...)");
                                Intrinsics.checkNotNullParameter(activity, "activity");
                                AbstractC1136h0 supportFragmentManager = activity.getSupportFragmentManager();
                                aVar.n = false;
                                aVar.o = true;
                                C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                                c1121aB.p = true;
                                c1121aB.i(0, aVar, "BillingErrorAlertDialog", 1);
                                if (c1121aB.g) {
                                    throw new IllegalStateException("This transaction is already being added to the back stack");
                                }
                                c1121aB.h = false;
                                c1121aB.r.B(c1121aB, false);
                            } else {
                                if (!(iVar instanceof com.quizlet.upgrade.manager.h)) {
                                    throw new NoWhenBranchMatchedException();
                                }
                                UpgradePackage upgradePackage = ((com.quizlet.upgrade.manager.h) iVar).a;
                                Bundle bundle2 = new Bundle(0);
                                bundle2.putInt("ResultUserUpgradeType", upgradePackage.b);
                                upgradeFragment.getParentFragmentManager().g0(bundle2, "UpgradeFragmentRequestKey");
                            }
                        }
                        return Unit.a;
                    case 1:
                        com.quizlet.upgrade.manager.d dVar = (com.quizlet.upgrade.manager.d) obj;
                        String str2 = UpgradeFragment.r;
                        if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.c.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_failed_to_upgrade, 1).show();
                        } else if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.a.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_unavailable_logged_out, 1).show();
                        } else {
                            if (!(dVar instanceof com.quizlet.upgrade.manager.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.upgrade.data.I i22 = ((com.quizlet.upgrade.manager.b) dVar).a;
                            com.quizlet.billing.subscriptions.h hVar = upgradeFragment.j;
                            if (hVar == null) {
                                Intrinsics.m("subscriptionHandler");
                                throw null;
                            }
                            I iRequireActivity = upgradeFragment.requireActivity();
                            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
                            com.quizlet.billing.subscriptions.j jVar = i22.a;
                            if (hVar.e == null) {
                                throw new IllegalStateException("onPurchaseCompleteListener is not initialized. Call setOnPurchaseCompleteListener() before checkout (launchPurchase()).");
                            }
                            com.quizlet.billing.model.b bVarE = hVar.b.e();
                            io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, hVar.i.f.e(new com.quizlet.billing.subscriptions.f(hVar, 2)), new com.google.firebase.tracing.a(6, hVar, jVar));
                            long j = bVarE.a;
                            String str3 = i22.b;
                            hVar.a(new io.reactivex.rxjava3.internal.operators.maybe.h(1, hVar2, new com.quizlet.billing.subscriptions.g(hVar, iRequireActivity, j, jVar, str3)).h(), j, str3);
                        }
                        return Unit.a;
                    case 2:
                        String str4 = UpgradeFragment.r;
                        a aVar2 = new a();
                        I activity2 = upgradeFragment.requireActivity();
                        Intrinsics.checkNotNullExpressionValue(activity2, "requireActivity(...)");
                        Intrinsics.checkNotNullParameter(activity2, "activity");
                        AbstractC1136h0 supportFragmentManager2 = activity2.getSupportFragmentManager();
                        aVar2.n = false;
                        aVar2.o = true;
                        C1121a c1121aB2 = B.b(supportFragmentManager2, supportFragmentManager2);
                        c1121aB2.p = true;
                        c1121aB2.i(0, aVar2, "BillingErrorAlertDialog", 1);
                        if (c1121aB2.g) {
                            throw new IllegalStateException("This transaction is already being added to the back stack");
                        }
                        c1121aB2.h = false;
                        c1121aB2.r.B(c1121aB2, false);
                        return Unit.a;
                    case 3:
                        String str5 = UpgradeFragment.r;
                        ((QuizletPlusLogo) ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).f.o).setLogoVariant((com.quizlet.ui.states.a) obj);
                        return Unit.a;
                    case 4:
                        String str6 = UpgradeFragment.r;
                        new TermsAndConditionsModalFragment().O(upgradeFragment.getChildFragmentManager(), TermsAndConditionsModalFragment.V);
                        return Unit.a;
                    case 5:
                        com.quizlet.upgrade.data.C c = (com.quizlet.upgrade.data.C) obj;
                        upgradeFragment.m.f(c.a);
                        upgradeFragment.n.f(c.b);
                        com.quizlet.upgrade.viewmodel.h hVarT = upgradeFragment.T();
                        m0 m0Var = hVarT.c;
                        Boolean bool = (Boolean) m0Var.a("skipToPlansState");
                        if (bool != null ? bool.booleanValue() : false) {
                            m0Var.c(Boolean.FALSE, "skipToPlansState");
                            E.A(p0.j(hVarT), null, null, new com.quizlet.upgrade.viewmodel.e(hVarT, null), 3);
                        }
                        return Unit.a;
                    case 6:
                        String str7 = UpgradeFragment.r;
                        new UpgradePlansModalFragment().O(upgradeFragment.getChildFragmentManager(), UpgradePlansModalFragment.W);
                        return Unit.a;
                    default:
                        String str8 = UpgradeFragment.r;
                        Y y = upgradeFragment.U().h;
                        Unit unit = Unit.a;
                        y.j(unit);
                        return unit;
                }
            }
        }));
        T().j.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new com.quizlet.search.composables.E(1, this, UpgradeFragment.class, "setUpHeader", "setUpHeader(Lcom/quizlet/upgrade/data/UpgradeHeaderState;)V", 0, 6)));
        final int i6 = 5;
        T().k.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new Function1(this) { // from class: com.quizlet.upgrade.ui.fragment.f
            public final /* synthetic */ UpgradeFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UpgradeFragment upgradeFragment = this.b;
                switch (i6) {
                    case 0:
                        com.quizlet.upgrade.manager.i iVar = (com.quizlet.upgrade.manager.i) obj;
                        String str = UpgradeFragment.r;
                        boolean z = iVar instanceof com.quizlet.upgrade.manager.g;
                        ProgressBar loadingProgress = ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).d;
                        Intrinsics.checkNotNullExpressionValue(loadingProgress, "loadingProgress");
                        loadingProgress.setVisibility(z ? 0 : 8);
                        if (!Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.b) && !Intrinsics.b(iVar, com.quizlet.upgrade.manager.g.a)) {
                            if (Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.a)) {
                                a aVar = new a();
                                I activity = upgradeFragment.requireActivity();
                                Intrinsics.checkNotNullExpressionValue(activity, "requireActivity(...)");
                                Intrinsics.checkNotNullParameter(activity, "activity");
                                AbstractC1136h0 supportFragmentManager = activity.getSupportFragmentManager();
                                aVar.n = false;
                                aVar.o = true;
                                C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                                c1121aB.p = true;
                                c1121aB.i(0, aVar, "BillingErrorAlertDialog", 1);
                                if (c1121aB.g) {
                                    throw new IllegalStateException("This transaction is already being added to the back stack");
                                }
                                c1121aB.h = false;
                                c1121aB.r.B(c1121aB, false);
                            } else {
                                if (!(iVar instanceof com.quizlet.upgrade.manager.h)) {
                                    throw new NoWhenBranchMatchedException();
                                }
                                UpgradePackage upgradePackage = ((com.quizlet.upgrade.manager.h) iVar).a;
                                Bundle bundle2 = new Bundle(0);
                                bundle2.putInt("ResultUserUpgradeType", upgradePackage.b);
                                upgradeFragment.getParentFragmentManager().g0(bundle2, "UpgradeFragmentRequestKey");
                            }
                        }
                        return Unit.a;
                    case 1:
                        com.quizlet.upgrade.manager.d dVar = (com.quizlet.upgrade.manager.d) obj;
                        String str2 = UpgradeFragment.r;
                        if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.c.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_failed_to_upgrade, 1).show();
                        } else if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.a.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_unavailable_logged_out, 1).show();
                        } else {
                            if (!(dVar instanceof com.quizlet.upgrade.manager.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.upgrade.data.I i22 = ((com.quizlet.upgrade.manager.b) dVar).a;
                            com.quizlet.billing.subscriptions.h hVar = upgradeFragment.j;
                            if (hVar == null) {
                                Intrinsics.m("subscriptionHandler");
                                throw null;
                            }
                            I iRequireActivity = upgradeFragment.requireActivity();
                            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
                            com.quizlet.billing.subscriptions.j jVar = i22.a;
                            if (hVar.e == null) {
                                throw new IllegalStateException("onPurchaseCompleteListener is not initialized. Call setOnPurchaseCompleteListener() before checkout (launchPurchase()).");
                            }
                            com.quizlet.billing.model.b bVarE = hVar.b.e();
                            io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, hVar.i.f.e(new com.quizlet.billing.subscriptions.f(hVar, 2)), new com.google.firebase.tracing.a(6, hVar, jVar));
                            long j = bVarE.a;
                            String str3 = i22.b;
                            hVar.a(new io.reactivex.rxjava3.internal.operators.maybe.h(1, hVar2, new com.quizlet.billing.subscriptions.g(hVar, iRequireActivity, j, jVar, str3)).h(), j, str3);
                        }
                        return Unit.a;
                    case 2:
                        String str4 = UpgradeFragment.r;
                        a aVar2 = new a();
                        I activity2 = upgradeFragment.requireActivity();
                        Intrinsics.checkNotNullExpressionValue(activity2, "requireActivity(...)");
                        Intrinsics.checkNotNullParameter(activity2, "activity");
                        AbstractC1136h0 supportFragmentManager2 = activity2.getSupportFragmentManager();
                        aVar2.n = false;
                        aVar2.o = true;
                        C1121a c1121aB2 = B.b(supportFragmentManager2, supportFragmentManager2);
                        c1121aB2.p = true;
                        c1121aB2.i(0, aVar2, "BillingErrorAlertDialog", 1);
                        if (c1121aB2.g) {
                            throw new IllegalStateException("This transaction is already being added to the back stack");
                        }
                        c1121aB2.h = false;
                        c1121aB2.r.B(c1121aB2, false);
                        return Unit.a;
                    case 3:
                        String str5 = UpgradeFragment.r;
                        ((QuizletPlusLogo) ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).f.o).setLogoVariant((com.quizlet.ui.states.a) obj);
                        return Unit.a;
                    case 4:
                        String str6 = UpgradeFragment.r;
                        new TermsAndConditionsModalFragment().O(upgradeFragment.getChildFragmentManager(), TermsAndConditionsModalFragment.V);
                        return Unit.a;
                    case 5:
                        com.quizlet.upgrade.data.C c = (com.quizlet.upgrade.data.C) obj;
                        upgradeFragment.m.f(c.a);
                        upgradeFragment.n.f(c.b);
                        com.quizlet.upgrade.viewmodel.h hVarT = upgradeFragment.T();
                        m0 m0Var = hVarT.c;
                        Boolean bool = (Boolean) m0Var.a("skipToPlansState");
                        if (bool != null ? bool.booleanValue() : false) {
                            m0Var.c(Boolean.FALSE, "skipToPlansState");
                            E.A(p0.j(hVarT), null, null, new com.quizlet.upgrade.viewmodel.e(hVarT, null), 3);
                        }
                        return Unit.a;
                    case 6:
                        String str7 = UpgradeFragment.r;
                        new UpgradePlansModalFragment().O(upgradeFragment.getChildFragmentManager(), UpgradePlansModalFragment.W);
                        return Unit.a;
                    default:
                        String str8 = UpgradeFragment.r;
                        Y y = upgradeFragment.U().h;
                        Unit unit = Unit.a;
                        y.j(unit);
                        return unit;
                }
            }
        }));
        T().l.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new com.quizlet.search.composables.E(1, this, UpgradeFragment.class, "setUpCTAState", "setUpCTAState(Lcom/quizlet/upgrade/data/UpgradeFeatureListCTAState;)V", 0, 7)));
        final int i7 = 6;
        T().m.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new Function1(this) { // from class: com.quizlet.upgrade.ui.fragment.f
            public final /* synthetic */ UpgradeFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UpgradeFragment upgradeFragment = this.b;
                switch (i7) {
                    case 0:
                        com.quizlet.upgrade.manager.i iVar = (com.quizlet.upgrade.manager.i) obj;
                        String str = UpgradeFragment.r;
                        boolean z = iVar instanceof com.quizlet.upgrade.manager.g;
                        ProgressBar loadingProgress = ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).d;
                        Intrinsics.checkNotNullExpressionValue(loadingProgress, "loadingProgress");
                        loadingProgress.setVisibility(z ? 0 : 8);
                        if (!Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.b) && !Intrinsics.b(iVar, com.quizlet.upgrade.manager.g.a)) {
                            if (Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.a)) {
                                a aVar = new a();
                                I activity = upgradeFragment.requireActivity();
                                Intrinsics.checkNotNullExpressionValue(activity, "requireActivity(...)");
                                Intrinsics.checkNotNullParameter(activity, "activity");
                                AbstractC1136h0 supportFragmentManager = activity.getSupportFragmentManager();
                                aVar.n = false;
                                aVar.o = true;
                                C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                                c1121aB.p = true;
                                c1121aB.i(0, aVar, "BillingErrorAlertDialog", 1);
                                if (c1121aB.g) {
                                    throw new IllegalStateException("This transaction is already being added to the back stack");
                                }
                                c1121aB.h = false;
                                c1121aB.r.B(c1121aB, false);
                            } else {
                                if (!(iVar instanceof com.quizlet.upgrade.manager.h)) {
                                    throw new NoWhenBranchMatchedException();
                                }
                                UpgradePackage upgradePackage = ((com.quizlet.upgrade.manager.h) iVar).a;
                                Bundle bundle2 = new Bundle(0);
                                bundle2.putInt("ResultUserUpgradeType", upgradePackage.b);
                                upgradeFragment.getParentFragmentManager().g0(bundle2, "UpgradeFragmentRequestKey");
                            }
                        }
                        return Unit.a;
                    case 1:
                        com.quizlet.upgrade.manager.d dVar = (com.quizlet.upgrade.manager.d) obj;
                        String str2 = UpgradeFragment.r;
                        if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.c.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_failed_to_upgrade, 1).show();
                        } else if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.a.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_unavailable_logged_out, 1).show();
                        } else {
                            if (!(dVar instanceof com.quizlet.upgrade.manager.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.upgrade.data.I i22 = ((com.quizlet.upgrade.manager.b) dVar).a;
                            com.quizlet.billing.subscriptions.h hVar = upgradeFragment.j;
                            if (hVar == null) {
                                Intrinsics.m("subscriptionHandler");
                                throw null;
                            }
                            I iRequireActivity = upgradeFragment.requireActivity();
                            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
                            com.quizlet.billing.subscriptions.j jVar = i22.a;
                            if (hVar.e == null) {
                                throw new IllegalStateException("onPurchaseCompleteListener is not initialized. Call setOnPurchaseCompleteListener() before checkout (launchPurchase()).");
                            }
                            com.quizlet.billing.model.b bVarE = hVar.b.e();
                            io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, hVar.i.f.e(new com.quizlet.billing.subscriptions.f(hVar, 2)), new com.google.firebase.tracing.a(6, hVar, jVar));
                            long j = bVarE.a;
                            String str3 = i22.b;
                            hVar.a(new io.reactivex.rxjava3.internal.operators.maybe.h(1, hVar2, new com.quizlet.billing.subscriptions.g(hVar, iRequireActivity, j, jVar, str3)).h(), j, str3);
                        }
                        return Unit.a;
                    case 2:
                        String str4 = UpgradeFragment.r;
                        a aVar2 = new a();
                        I activity2 = upgradeFragment.requireActivity();
                        Intrinsics.checkNotNullExpressionValue(activity2, "requireActivity(...)");
                        Intrinsics.checkNotNullParameter(activity2, "activity");
                        AbstractC1136h0 supportFragmentManager2 = activity2.getSupportFragmentManager();
                        aVar2.n = false;
                        aVar2.o = true;
                        C1121a c1121aB2 = B.b(supportFragmentManager2, supportFragmentManager2);
                        c1121aB2.p = true;
                        c1121aB2.i(0, aVar2, "BillingErrorAlertDialog", 1);
                        if (c1121aB2.g) {
                            throw new IllegalStateException("This transaction is already being added to the back stack");
                        }
                        c1121aB2.h = false;
                        c1121aB2.r.B(c1121aB2, false);
                        return Unit.a;
                    case 3:
                        String str5 = UpgradeFragment.r;
                        ((QuizletPlusLogo) ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).f.o).setLogoVariant((com.quizlet.ui.states.a) obj);
                        return Unit.a;
                    case 4:
                        String str6 = UpgradeFragment.r;
                        new TermsAndConditionsModalFragment().O(upgradeFragment.getChildFragmentManager(), TermsAndConditionsModalFragment.V);
                        return Unit.a;
                    case 5:
                        com.quizlet.upgrade.data.C c = (com.quizlet.upgrade.data.C) obj;
                        upgradeFragment.m.f(c.a);
                        upgradeFragment.n.f(c.b);
                        com.quizlet.upgrade.viewmodel.h hVarT = upgradeFragment.T();
                        m0 m0Var = hVarT.c;
                        Boolean bool = (Boolean) m0Var.a("skipToPlansState");
                        if (bool != null ? bool.booleanValue() : false) {
                            m0Var.c(Boolean.FALSE, "skipToPlansState");
                            E.A(p0.j(hVarT), null, null, new com.quizlet.upgrade.viewmodel.e(hVarT, null), 3);
                        }
                        return Unit.a;
                    case 6:
                        String str7 = UpgradeFragment.r;
                        new UpgradePlansModalFragment().O(upgradeFragment.getChildFragmentManager(), UpgradePlansModalFragment.W);
                        return Unit.a;
                    default:
                        String str8 = UpgradeFragment.r;
                        Y y = upgradeFragment.U().h;
                        Unit unit = Unit.a;
                        y.j(unit);
                        return unit;
                }
            }
        }));
        T().n.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new com.quizlet.search.composables.E(1, this, UpgradeFragment.class, "showHelpCenter", "showHelpCenter(Lcom/quizlet/upgrade/data/UpgradeHelpCenterType;)V", 0, 3)));
        final int i8 = 7;
        T().o.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new Function1(this) { // from class: com.quizlet.upgrade.ui.fragment.f
            public final /* synthetic */ UpgradeFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UpgradeFragment upgradeFragment = this.b;
                switch (i8) {
                    case 0:
                        com.quizlet.upgrade.manager.i iVar = (com.quizlet.upgrade.manager.i) obj;
                        String str = UpgradeFragment.r;
                        boolean z = iVar instanceof com.quizlet.upgrade.manager.g;
                        ProgressBar loadingProgress = ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).d;
                        Intrinsics.checkNotNullExpressionValue(loadingProgress, "loadingProgress");
                        loadingProgress.setVisibility(z ? 0 : 8);
                        if (!Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.b) && !Intrinsics.b(iVar, com.quizlet.upgrade.manager.g.a)) {
                            if (Intrinsics.b(iVar, com.quizlet.upgrade.manager.f.a)) {
                                a aVar = new a();
                                I activity = upgradeFragment.requireActivity();
                                Intrinsics.checkNotNullExpressionValue(activity, "requireActivity(...)");
                                Intrinsics.checkNotNullParameter(activity, "activity");
                                AbstractC1136h0 supportFragmentManager = activity.getSupportFragmentManager();
                                aVar.n = false;
                                aVar.o = true;
                                C1121a c1121aB = B.b(supportFragmentManager, supportFragmentManager);
                                c1121aB.p = true;
                                c1121aB.i(0, aVar, "BillingErrorAlertDialog", 1);
                                if (c1121aB.g) {
                                    throw new IllegalStateException("This transaction is already being added to the back stack");
                                }
                                c1121aB.h = false;
                                c1121aB.r.B(c1121aB, false);
                            } else {
                                if (!(iVar instanceof com.quizlet.upgrade.manager.h)) {
                                    throw new NoWhenBranchMatchedException();
                                }
                                UpgradePackage upgradePackage = ((com.quizlet.upgrade.manager.h) iVar).a;
                                Bundle bundle2 = new Bundle(0);
                                bundle2.putInt("ResultUserUpgradeType", upgradePackage.b);
                                upgradeFragment.getParentFragmentManager().g0(bundle2, "UpgradeFragmentRequestKey");
                            }
                        }
                        return Unit.a;
                    case 1:
                        com.quizlet.upgrade.manager.d dVar = (com.quizlet.upgrade.manager.d) obj;
                        String str2 = UpgradeFragment.r;
                        if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.c.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_failed_to_upgrade, 1).show();
                        } else if (Intrinsics.b(dVar, com.quizlet.upgrade.manager.a.a)) {
                            Toast.makeText(upgradeFragment.requireContext(), R.string.upgrade_unavailable_logged_out, 1).show();
                        } else {
                            if (!(dVar instanceof com.quizlet.upgrade.manager.b)) {
                                throw new NoWhenBranchMatchedException();
                            }
                            com.quizlet.upgrade.data.I i22 = ((com.quizlet.upgrade.manager.b) dVar).a;
                            com.quizlet.billing.subscriptions.h hVar = upgradeFragment.j;
                            if (hVar == null) {
                                Intrinsics.m("subscriptionHandler");
                                throw null;
                            }
                            I iRequireActivity = upgradeFragment.requireActivity();
                            Intrinsics.checkNotNullExpressionValue(iRequireActivity, "requireActivity(...)");
                            com.quizlet.billing.subscriptions.j jVar = i22.a;
                            if (hVar.e == null) {
                                throw new IllegalStateException("onPurchaseCompleteListener is not initialized. Call setOnPurchaseCompleteListener() before checkout (launchPurchase()).");
                            }
                            com.quizlet.billing.model.b bVarE = hVar.b.e();
                            io.reactivex.rxjava3.internal.operators.maybe.h hVar2 = new io.reactivex.rxjava3.internal.operators.maybe.h(3, hVar.i.f.e(new com.quizlet.billing.subscriptions.f(hVar, 2)), new com.google.firebase.tracing.a(6, hVar, jVar));
                            long j = bVarE.a;
                            String str3 = i22.b;
                            hVar.a(new io.reactivex.rxjava3.internal.operators.maybe.h(1, hVar2, new com.quizlet.billing.subscriptions.g(hVar, iRequireActivity, j, jVar, str3)).h(), j, str3);
                        }
                        return Unit.a;
                    case 2:
                        String str4 = UpgradeFragment.r;
                        a aVar2 = new a();
                        I activity2 = upgradeFragment.requireActivity();
                        Intrinsics.checkNotNullExpressionValue(activity2, "requireActivity(...)");
                        Intrinsics.checkNotNullParameter(activity2, "activity");
                        AbstractC1136h0 supportFragmentManager2 = activity2.getSupportFragmentManager();
                        aVar2.n = false;
                        aVar2.o = true;
                        C1121a c1121aB2 = B.b(supportFragmentManager2, supportFragmentManager2);
                        c1121aB2.p = true;
                        c1121aB2.i(0, aVar2, "BillingErrorAlertDialog", 1);
                        if (c1121aB2.g) {
                            throw new IllegalStateException("This transaction is already being added to the back stack");
                        }
                        c1121aB2.h = false;
                        c1121aB2.r.B(c1121aB2, false);
                        return Unit.a;
                    case 3:
                        String str5 = UpgradeFragment.r;
                        ((QuizletPlusLogo) ((com.quizlet.upgrade.databinding.c) upgradeFragment.J()).f.o).setLogoVariant((com.quizlet.ui.states.a) obj);
                        return Unit.a;
                    case 4:
                        String str6 = UpgradeFragment.r;
                        new TermsAndConditionsModalFragment().O(upgradeFragment.getChildFragmentManager(), TermsAndConditionsModalFragment.V);
                        return Unit.a;
                    case 5:
                        com.quizlet.upgrade.data.C c = (com.quizlet.upgrade.data.C) obj;
                        upgradeFragment.m.f(c.a);
                        upgradeFragment.n.f(c.b);
                        com.quizlet.upgrade.viewmodel.h hVarT = upgradeFragment.T();
                        m0 m0Var = hVarT.c;
                        Boolean bool = (Boolean) m0Var.a("skipToPlansState");
                        if (bool != null ? bool.booleanValue() : false) {
                            m0Var.c(Boolean.FALSE, "skipToPlansState");
                            E.A(p0.j(hVarT), null, null, new com.quizlet.upgrade.viewmodel.e(hVarT, null), 3);
                        }
                        return Unit.a;
                    case 6:
                        String str7 = UpgradeFragment.r;
                        new UpgradePlansModalFragment().O(upgradeFragment.getChildFragmentManager(), UpgradePlansModalFragment.W);
                        return Unit.a;
                    default:
                        String str8 = UpgradeFragment.r;
                        Y y = upgradeFragment.U().h;
                        Unit unit = Unit.a;
                        y.j(unit);
                        return unit;
                }
            }
        }));
        com.quizlet.explanations.solution.recyclerview.step.l lVar = this.n;
        ((X) lVar.d).f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(26, new com.quizlet.search.composables.E(1, U(), com.quizlet.upgrade.viewmodel.n.class, "onFooterItemClicked", "onFooterItemClicked(Lcom/quizlet/upgrade/data/UpgradeFeatureFooter;)V", 0, 4)));
        com.quizlet.upgrade.databinding.c cVar = (com.quizlet.upgrade.databinding.c) J();
        requireContext();
        cVar.e.setLayoutManager(new LinearLayoutManager(1));
        C1370i c1370i = new C1370i(new AbstractC1361d0[0]);
        c1370i.d(this.m);
        c1370i.d(lVar);
        ((com.quizlet.upgrade.databinding.c) J()).e.setAdapter(c1370i);
        ((AssemblyTextButton) ((com.quizlet.upgrade.databinding.c) J()).b.b).setOnClickListener(new d(this, 1));
    }
}
