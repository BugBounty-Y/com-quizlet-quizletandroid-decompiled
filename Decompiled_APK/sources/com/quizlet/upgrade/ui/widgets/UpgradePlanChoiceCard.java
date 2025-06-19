package com.quizlet.upgrade.ui.widgets;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.onetrust.otpublishers.headless.databinding.e;
import com.quizlet.assembly.widgets.AssemblyCard;
import com.quizlet.assembly.widgets.AssemblyPill;
import com.quizlet.quizletandroid.R;
import com.quizlet.qutils.string.g;
import com.skydoves.balloon.internals.DefinitionKt;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class UpgradePlanChoiceCard extends ConstraintLayout {
    public final e q;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public UpgradePlanChoiceCard(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    public final void p(a state) {
        Intrinsics.checkNotNullParameter(state, "state");
        e eVar = this.q;
        TextView textView = eVar.i;
        g gVar = state.a;
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        textView.setText(gVar.a(context));
        TextView textView2 = (TextView) eVar.h;
        Context context2 = getContext();
        Intrinsics.checkNotNullExpressionValue(context2, "getContext(...)");
        textView2.setText(AbstractC3053s1.e(state.b, context2));
        TextView textView3 = eVar.d;
        Context context3 = getContext();
        Intrinsics.checkNotNullExpressionValue(context3, "getContext(...)");
        textView3.setText(AbstractC3053s1.e(state.c, context3));
        TextView textView4 = eVar.f;
        Context context4 = getContext();
        Intrinsics.checkNotNullExpressionValue(context4, "getContext(...)");
        textView4.setText(AbstractC3053s1.e(state.d, context4));
        AssemblyPill bestValuePill = (AssemblyPill) eVar.g;
        Intrinsics.checkNotNullExpressionValue(bestValuePill, "bestValuePill");
        bestValuePill.setVisibility(state.e ? 0 : 8);
    }

    public final void q() {
        float dimension = isSelected() ? getContext().getResources().getDimension(R.dimen.card_elevation) : DefinitionKt.NO_Float_VALUE;
        e eVar = this.q;
        ((AssemblyCard) eVar.c).setCardElevation(dimension);
        ((AssemblyPill) eVar.g).setElevation(dimension);
    }

    @Override // android.view.View
    public void setSelected(boolean z) {
        super.setSelected(z);
        ImageView selectedPlanCheckMark = (ImageView) this.q.e;
        Intrinsics.checkNotNullExpressionValue(selectedPlanCheckMark, "selectedPlanCheckMark");
        selectedPlanCheckMark.setVisibility(z ? 0 : 8);
        q();
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public UpgradePlanChoiceCard(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public UpgradePlanChoiceCard(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        LayoutInflater.from(context).inflate(R.layout.view_upgrade_plan_choice_card, this);
        int i2 = R.id.bestValuePill;
        AssemblyPill assemblyPill = (AssemblyPill) AbstractC3375o2.c(R.id.bestValuePill, this);
        if (assemblyPill != null) {
            i2 = R.id.planChoiceCard;
            AssemblyCard assemblyCard = (AssemblyCard) AbstractC3375o2.c(R.id.planChoiceCard, this);
            if (assemblyCard != null) {
                i2 = R.id.planFrequency;
                TextView textView = (TextView) AbstractC3375o2.c(R.id.planFrequency, this);
                if (textView != null) {
                    i2 = R.id.planInfo;
                    TextView textView2 = (TextView) AbstractC3375o2.c(R.id.planInfo, this);
                    if (textView2 != null) {
                        i2 = R.id.planPrice;
                        TextView textView3 = (TextView) AbstractC3375o2.c(R.id.planPrice, this);
                        if (textView3 != null) {
                            i2 = R.id.planType;
                            TextView textView4 = (TextView) AbstractC3375o2.c(R.id.planType, this);
                            if (textView4 != null) {
                                i2 = R.id.selectedPlanCheckMark;
                                ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.selectedPlanCheckMark, this);
                                if (imageView != null) {
                                    e eVar = new e(this, assemblyPill, assemblyCard, textView, textView2, textView3, textView4, imageView);
                                    Intrinsics.checkNotNullExpressionValue(eVar, "inflate(...)");
                                    this.q = eVar;
                                    q();
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(i2)));
    }
}
