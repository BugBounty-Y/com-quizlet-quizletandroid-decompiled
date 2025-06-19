package com.quizlet.features.setpage.progress.presentation.ui;

import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.ViewGroup;
import android.widget.ImageView;
import androidx.cardview.widget.CardView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.explanations.databinding.n;
import com.quizlet.features.setpage.d;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.views.ArcProgressBar;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class SetPageProgressItemView extends CardView {
    public final n h;
    public final int i;
    public final int j;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public SetPageProgressItemView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final void setupEnableStatusUi(boolean z) {
        n nVar = this.h;
        QTextView qTextView = (QTextView) nVar.d;
        int i = this.j;
        int i2 = this.i;
        qTextView.setTextColor(z ? i2 : i);
        if (z) {
            i = i2;
        }
        ((QTextView) nVar.e).setTextColor(i);
        Context context = getContext();
        Intrinsics.checkNotNullExpressionValue(context, "getContext(...)");
        ((ImageView) nVar.b).setImageDrawable(com.quizlet.themes.extensions.a.c(context, R.drawable.ic_sys_arrow_right, z ? R.attr.stateClickable : R.attr.stateDisabled));
    }

    @Override // android.view.View
    public final boolean performClick() {
        ((ConstraintLayout) this.h.c).performClick();
        return super.performClick();
    }

    @Override // android.view.View
    public void setEnabled(boolean z) {
        boolean zIsEnabled = isEnabled();
        super.setEnabled(z);
        if (z != zIsEnabled) {
            setupEnableStatusUi(z);
        }
    }

    public final void setProgressBackgroundColor(int i) {
        ((ArcProgressBar) this.h.g).setBackgroundColor(i);
    }

    public final void setProgressColor(int i) {
        ((ArcProgressBar) this.h.g).setColor(i);
    }

    public final void setStatusText(CharSequence charSequence) {
        ((QTextView) this.h.e).setText(charSequence);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public SetPageProgressItemView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public SetPageProgressItemView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        LayoutInflater.from(context).inflate(R.layout.set_page_progress_item_view, (ViewGroup) this, true);
        int i2 = R.id.imageViewIcon;
        ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.imageViewIcon, this);
        if (imageView != null) {
            i2 = R.id.progressBar;
            ArcProgressBar arcProgressBar = (ArcProgressBar) AbstractC3375o2.c(R.id.progressBar, this);
            if (arcProgressBar != null) {
                i2 = R.id.progressContainer;
                ConstraintLayout constraintLayout = (ConstraintLayout) AbstractC3375o2.c(R.id.progressContainer, this);
                if (constraintLayout != null) {
                    i2 = R.id.textViewNumber;
                    QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.textViewNumber, this);
                    if (qTextView != null) {
                        i2 = R.id.textViewStatus;
                        QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.textViewStatus, this);
                        if (qTextView2 != null) {
                            this.h = new n(this, imageView, arcProgressBar, constraintLayout, qTextView, qTextView2);
                            setCardBackgroundColor(com.quizlet.themes.extensions.a.a(context, R.attr.SysColorCard));
                            this.i = com.quizlet.themes.extensions.a.a(context, R.attr.textColor);
                            this.j = com.quizlet.themes.extensions.a.a(context, R.attr.textColorDisabled);
                            setRadius(getResources().getDimensionPixelOffset(R.dimen.ref_radius_medium));
                            if (attributeSet != null) {
                                TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, d.a);
                                Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
                                CharSequence text = typedArrayObtainStyledAttributes.getText(3);
                                int color = typedArrayObtainStyledAttributes.getColor(2, arcProgressBar.getColor());
                                int color2 = typedArrayObtainStyledAttributes.getColor(1, arcProgressBar.getBackgroundColor());
                                setStatusText(text);
                                setProgressColor(color);
                                setProgressBackgroundColor(color2);
                                typedArrayObtainStyledAttributes.recycle();
                                return;
                            }
                            return;
                        }
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(i2)));
    }
}
