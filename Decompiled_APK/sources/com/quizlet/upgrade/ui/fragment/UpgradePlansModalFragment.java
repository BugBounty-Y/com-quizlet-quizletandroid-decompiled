package com.quizlet.upgrade.ui.fragment;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.widget.NestedScrollView;
import androidx.fragment.app.AbstractC1136h0;
import androidx.lifecycle.Y;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblyTextButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.quizletandroid.ui.studymodes.match.fragment.t;
import com.quizlet.search.composables.E;
import com.quizlet.upgrade.ui.widgets.UpgradePlanChoiceCard;
import com.quizlet.upgrade.ui.widgets.UpgradeTimelineSectionLayout;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.K;
import kotlin.u;

@Metadata
/* loaded from: classes3.dex */
public final class UpgradePlansModalFragment extends Hilt_UpgradePlansModalFragment {
    public static final String W;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e I;
    public final com.quizlet.data.repository.folderwithcreatorinclass.e J;
    public com.quizlet.upgrade.databinding.b K;
    public final u L;
    public final com.quizlet.uicommon.ui.common.dialogs.b M;
    public final boolean V;

    static {
        Intrinsics.checkNotNullExpressionValue("UpgradePlansModalFragment", "getSimpleName(...)");
        W = "UpgradePlansModalFragment";
    }

    public UpgradePlansModalFragment() {
        kotlin.k kVarA = kotlin.l.a(kotlin.m.c, new t(new t(this, 12), 13));
        this.I = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.upgrade.viewmodel.k.class), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 21), new m(0, this, kVarA), new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.i(kVarA, 22));
        this.J = new com.quizlet.data.repository.folderwithcreatorinclass.e(K.a(com.quizlet.upgrade.viewmodel.n.class), new l(this, 0), new l(this, 2), new l(this, 1));
        this.L = kotlin.l.b(new com.quizlet.quizletandroid.ui.studymodes.assistant.settings.grading.a(this, 15));
        this.M = com.quizlet.uicommon.ui.common.dialogs.b.a;
        this.V = true;
    }

    public static void d0(UpgradeTimelineSectionLayout upgradeTimelineSectionLayout, com.quizlet.upgrade.ui.widgets.b state) {
        upgradeTimelineSectionLayout.setVisibility(state != null ? 0 : 8);
        if (state != null) {
            Intrinsics.checkNotNullParameter(state, "state");
            com.quizlet.features.infra.legacyadapter.databinding.h hVar = upgradeTimelineSectionLayout.q;
            ((ImageView) hVar.c).setImageResource(state.a);
            Context context = upgradeTimelineSectionLayout.getContext();
            Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
            ((TextView) hVar.b).setText(AbstractC3053s1.e(state.b, context));
            Context context2 = upgradeTimelineSectionLayout.getContext();
            Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
            ((TextView) hVar.d).setText(state.c.a(context2));
            View line = (View) hVar.f;
            Intrinsics.checkNotNullExpressionValue(line, "line");
            line.setVisibility(state.d ? 0 : 8);
            upgradeTimelineSectionLayout.setSelected(state.e);
        }
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final void R(FrameLayout container, AbstractC1136h0 fragmentManager) {
        Intrinsics.checkNotNullParameter(container, "container");
        Intrinsics.checkNotNullParameter(fragmentManager, "fragmentManager");
        container.addView(c0().a);
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.BaseViewBindingConvertibleModalDialogFragment
    public final com.quizlet.uicommon.ui.common.dialogs.b S() {
        return this.M;
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment
    public final String W() {
        return (String) this.L.getValue();
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment
    public final boolean X() {
        return this.V;
    }

    public final com.quizlet.upgrade.databinding.b c0() {
        com.quizlet.upgrade.databinding.b bVar = this.K;
        if (bVar != null) {
            return bVar;
        }
        throw new IllegalStateException("View binding is only valid between onCreateView and onDestroyView");
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, androidx.fragment.app.Fragment
    public final View onCreateView(LayoutInflater inflater, ViewGroup viewGroup, Bundle bundle) {
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        View viewInflate = inflater.inflate(R.layout.fragment_upgrade_plans, viewGroup, false);
        int i = R.id.annualPlan;
        UpgradePlanChoiceCard upgradePlanChoiceCard = (UpgradePlanChoiceCard) AbstractC3375o2.c(R.id.annualPlan, viewInflate);
        if (upgradePlanChoiceCard != null) {
            i = R.id.monthlyPlan;
            UpgradePlanChoiceCard upgradePlanChoiceCard2 = (UpgradePlanChoiceCard) AbstractC3375o2.c(R.id.monthlyPlan, viewInflate);
            if (upgradePlanChoiceCard2 != null) {
                i = R.id.scrollContainer;
                if (((NestedScrollView) AbstractC3375o2.c(R.id.scrollContainer, viewInflate)) != null) {
                    i = R.id.subscribeButton;
                    AssemblyPrimaryButton assemblyPrimaryButton = (AssemblyPrimaryButton) AbstractC3375o2.c(R.id.subscribeButton, viewInflate);
                    if (assemblyPrimaryButton != null) {
                        i = R.id.termsAndConditionsButton;
                        AssemblyTextButton assemblyTextButton = (AssemblyTextButton) AbstractC3375o2.c(R.id.termsAndConditionsButton, viewInflate);
                        if (assemblyTextButton != null) {
                            i = R.id.timelineFirstTask;
                            UpgradeTimelineSectionLayout upgradeTimelineSectionLayout = (UpgradeTimelineSectionLayout) AbstractC3375o2.c(R.id.timelineFirstTask, viewInflate);
                            if (upgradeTimelineSectionLayout != null) {
                                i = R.id.timelineHeading;
                                QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.timelineHeading, viewInflate);
                                if (qTextView != null) {
                                    i = R.id.timelineSecondTask;
                                    UpgradeTimelineSectionLayout upgradeTimelineSectionLayout2 = (UpgradeTimelineSectionLayout) AbstractC3375o2.c(R.id.timelineSecondTask, viewInflate);
                                    if (upgradeTimelineSectionLayout2 != null) {
                                        i = R.id.timelineThirdTask;
                                        UpgradeTimelineSectionLayout upgradeTimelineSectionLayout3 = (UpgradeTimelineSectionLayout) AbstractC3375o2.c(R.id.timelineThirdTask, viewInflate);
                                        if (upgradeTimelineSectionLayout3 != null) {
                                            this.K = new com.quizlet.upgrade.databinding.b((ConstraintLayout) viewInflate, upgradePlanChoiceCard, upgradePlanChoiceCard2, assemblyPrimaryButton, assemblyTextButton, upgradeTimelineSectionLayout, qTextView, upgradeTimelineSectionLayout2, upgradeTimelineSectionLayout3);
                                            return super.onCreateView(inflater, viewGroup, bundle);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(viewInflate.getResources().getResourceName(i)));
    }

    @Override // com.quizlet.baseui.base.BaseViewBindingDialogFragment, com.quizlet.baseui.base.BaseDaggerDialogFragment, androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, androidx.fragment.app.Fragment
    public final void onDestroyView() {
        this.K = null;
        super.onDestroyView();
    }

    @Override // com.quizlet.uicommon.ui.common.dialogs.FullScreenConvertibleModalDialogFragment, androidx.fragment.app.Fragment
    public final void onViewCreated(View view, Bundle bundle) {
        Intrinsics.checkNotNullParameter(view, "view");
        super.onViewCreated(view, bundle);
        final int i = 0;
        ((Y) ((com.quizlet.upgrade.viewmodel.n) this.J.getValue()).d.e).f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(27, new Function1(this) { // from class: com.quizlet.upgrade.ui.fragment.j
            public final /* synthetic */ UpgradePlansModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UpgradePlansModalFragment upgradePlansModalFragment = this.b;
                switch (i) {
                    case 0:
                        String str = UpgradePlansModalFragment.W;
                        if (((com.quizlet.upgrade.manager.i) obj) instanceof com.quizlet.upgrade.manager.h) {
                            upgradePlansModalFragment.H(false, false);
                        }
                        return Unit.a;
                    default:
                        String str2 = UpgradePlansModalFragment.W;
                        Y y = ((com.quizlet.upgrade.viewmodel.n) upgradePlansModalFragment.J.getValue()).h;
                        Unit unit = Unit.a;
                        y.j(unit);
                        return unit;
                }
            }
        }));
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar = this.I;
        ((com.quizlet.upgrade.viewmodel.k) eVar.getValue()).e.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(27, new E(1, this, UpgradePlansModalFragment.class, "setPlanChoiceButtonState", "setPlanChoiceButtonState(Lcom/quizlet/upgrade/data/UpgradePlanChoiceButtonState;)V", 0, 8)));
        ((com.quizlet.upgrade.viewmodel.k) eVar.getValue()).f.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(27, new E(1, this, UpgradePlansModalFragment.class, "toggleSelectedPlan", "toggleSelectedPlan(Lcom/quizlet/upgrade/data/SelectedUpgradePlan;)V", 0, 9)));
        final int i2 = 1;
        ((com.quizlet.upgrade.viewmodel.k) eVar.getValue()).g.f(getViewLifecycleOwner(), new com.quizlet.explanations.feedback.ui.fragments.c(27, new Function1(this) { // from class: com.quizlet.upgrade.ui.fragment.j
            public final /* synthetic */ UpgradePlansModalFragment b;

            {
                this.b = this;
            }

            @Override // kotlin.jvm.functions.Function1
            public final Object invoke(Object obj) {
                UpgradePlansModalFragment upgradePlansModalFragment = this.b;
                switch (i2) {
                    case 0:
                        String str = UpgradePlansModalFragment.W;
                        if (((com.quizlet.upgrade.manager.i) obj) instanceof com.quizlet.upgrade.manager.h) {
                            upgradePlansModalFragment.H(false, false);
                        }
                        return Unit.a;
                    default:
                        String str2 = UpgradePlansModalFragment.W;
                        Y y = ((com.quizlet.upgrade.viewmodel.n) upgradePlansModalFragment.J.getValue()).h;
                        Unit unit = Unit.a;
                        y.j(unit);
                        return unit;
                }
            }
        }));
        com.quizlet.upgrade.databinding.b bVarC0 = c0();
        final int i3 = 0;
        bVarC0.b.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.upgrade.ui.fragment.k
            public final /* synthetic */ UpgradePlansModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                UpgradePlansModalFragment upgradePlansModalFragment = this.b;
                switch (i3) {
                    case 0:
                        String str = UpgradePlansModalFragment.W;
                        com.quizlet.upgrade.viewmodel.k kVar = (com.quizlet.upgrade.viewmodel.k) upgradePlansModalFragment.I.getValue();
                        com.quizlet.upgrade.data.m mVar = kVar.h;
                        if (mVar != null) {
                            kVar.f.j(mVar);
                            break;
                        }
                        break;
                    case 1:
                        String str2 = UpgradePlansModalFragment.W;
                        com.quizlet.upgrade.viewmodel.k kVar2 = (com.quizlet.upgrade.viewmodel.k) upgradePlansModalFragment.I.getValue();
                        com.quizlet.upgrade.data.l lVar = kVar2.i;
                        if (lVar != null) {
                            kVar2.f.j(lVar);
                            break;
                        }
                        break;
                    default:
                        String str3 = UpgradePlansModalFragment.W;
                        ((com.quizlet.upgrade.viewmodel.n) upgradePlansModalFragment.J.getValue()).g.j(Unit.a);
                        break;
                }
            }
        });
        com.quizlet.upgrade.databinding.b bVarC02 = c0();
        final int i4 = 1;
        bVarC02.c.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.upgrade.ui.fragment.k
            public final /* synthetic */ UpgradePlansModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                UpgradePlansModalFragment upgradePlansModalFragment = this.b;
                switch (i4) {
                    case 0:
                        String str = UpgradePlansModalFragment.W;
                        com.quizlet.upgrade.viewmodel.k kVar = (com.quizlet.upgrade.viewmodel.k) upgradePlansModalFragment.I.getValue();
                        com.quizlet.upgrade.data.m mVar = kVar.h;
                        if (mVar != null) {
                            kVar.f.j(mVar);
                            break;
                        }
                        break;
                    case 1:
                        String str2 = UpgradePlansModalFragment.W;
                        com.quizlet.upgrade.viewmodel.k kVar2 = (com.quizlet.upgrade.viewmodel.k) upgradePlansModalFragment.I.getValue();
                        com.quizlet.upgrade.data.l lVar = kVar2.i;
                        if (lVar != null) {
                            kVar2.f.j(lVar);
                            break;
                        }
                        break;
                    default:
                        String str3 = UpgradePlansModalFragment.W;
                        ((com.quizlet.upgrade.viewmodel.n) upgradePlansModalFragment.J.getValue()).g.j(Unit.a);
                        break;
                }
            }
        });
        com.quizlet.upgrade.databinding.b bVarC03 = c0();
        final int i5 = 2;
        bVarC03.e.setOnClickListener(new View.OnClickListener(this) { // from class: com.quizlet.upgrade.ui.fragment.k
            public final /* synthetic */ UpgradePlansModalFragment b;

            {
                this.b = this;
            }

            @Override // android.view.View.OnClickListener
            public final void onClick(View view2) {
                UpgradePlansModalFragment upgradePlansModalFragment = this.b;
                switch (i5) {
                    case 0:
                        String str = UpgradePlansModalFragment.W;
                        com.quizlet.upgrade.viewmodel.k kVar = (com.quizlet.upgrade.viewmodel.k) upgradePlansModalFragment.I.getValue();
                        com.quizlet.upgrade.data.m mVar = kVar.h;
                        if (mVar != null) {
                            kVar.f.j(mVar);
                            break;
                        }
                        break;
                    case 1:
                        String str2 = UpgradePlansModalFragment.W;
                        com.quizlet.upgrade.viewmodel.k kVar2 = (com.quizlet.upgrade.viewmodel.k) upgradePlansModalFragment.I.getValue();
                        com.quizlet.upgrade.data.l lVar = kVar2.i;
                        if (lVar != null) {
                            kVar2.f.j(lVar);
                            break;
                        }
                        break;
                    default:
                        String str3 = UpgradePlansModalFragment.W;
                        ((com.quizlet.upgrade.viewmodel.n) upgradePlansModalFragment.J.getValue()).g.j(Unit.a);
                        break;
                }
            }
        });
    }
}
