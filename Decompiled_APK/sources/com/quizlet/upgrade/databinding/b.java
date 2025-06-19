package com.quizlet.upgrade.databinding;

import android.view.View;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.quizlet.assembly.widgets.buttons.AssemblyPrimaryButton;
import com.quizlet.assembly.widgets.buttons.AssemblyTextButton;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.upgrade.ui.widgets.UpgradePlanChoiceCard;
import com.quizlet.upgrade.ui.widgets.UpgradeTimelineSectionLayout;

/* loaded from: classes3.dex */
public final class b implements androidx.viewbinding.a {
    public final ConstraintLayout a;
    public final UpgradePlanChoiceCard b;
    public final UpgradePlanChoiceCard c;
    public final AssemblyPrimaryButton d;
    public final AssemblyTextButton e;
    public final UpgradeTimelineSectionLayout f;
    public final QTextView g;
    public final UpgradeTimelineSectionLayout h;
    public final UpgradeTimelineSectionLayout i;

    public b(ConstraintLayout constraintLayout, UpgradePlanChoiceCard upgradePlanChoiceCard, UpgradePlanChoiceCard upgradePlanChoiceCard2, AssemblyPrimaryButton assemblyPrimaryButton, AssemblyTextButton assemblyTextButton, UpgradeTimelineSectionLayout upgradeTimelineSectionLayout, QTextView qTextView, UpgradeTimelineSectionLayout upgradeTimelineSectionLayout2, UpgradeTimelineSectionLayout upgradeTimelineSectionLayout3) {
        this.a = constraintLayout;
        this.b = upgradePlanChoiceCard;
        this.c = upgradePlanChoiceCard2;
        this.d = assemblyPrimaryButton;
        this.e = assemblyTextButton;
        this.f = upgradeTimelineSectionLayout;
        this.g = qTextView;
        this.h = upgradeTimelineSectionLayout2;
        this.i = upgradeTimelineSectionLayout3;
    }

    @Override // androidx.viewbinding.a
    public final View getRoot() {
        return this.a;
    }
}
