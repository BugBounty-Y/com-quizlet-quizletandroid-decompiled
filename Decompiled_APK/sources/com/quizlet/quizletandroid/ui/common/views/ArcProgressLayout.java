package com.quizlet.quizletandroid.ui.common.views;

import android.content.Context;
import android.content.res.TypedArray;
import android.text.SpannableStringBuilder;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.widget.FrameLayout;
import android.widget.TextView;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.features.infra.legacyadapter.databinding.f;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.I;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.views.ArcProgressBar;
import java.text.NumberFormat;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ArcProgressLayout extends FrameLayout {
    public final f a;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ArcProgressLayout(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    private final ArcProgressBar getHeaderProgress() {
        ArcProgressBar arcProgressBar = (ArcProgressBar) this.a.c;
        Intrinsics.checkNotNullExpressionValue(arcProgressBar, "arcProgressBar");
        return arcProgressBar;
    }

    private final TextView getHeaderScore() {
        QTextView arcProgressValue = (QTextView) this.a.e;
        Intrinsics.checkNotNullExpressionValue(arcProgressValue, "arcProgressValue");
        return arcProgressValue;
    }

    private final TextView getHeaderText() {
        QTextView arcProgressLabel = (QTextView) this.a.d;
        Intrinsics.checkNotNullExpressionValue(arcProgressLabel, "arcProgressLabel");
        return arcProgressLabel;
    }

    public final void setScore(int i) {
        NumberFormat percentInstance = NumberFormat.getPercentInstance();
        Intrinsics.checkNotNullExpressionValue(percentInstance, "getPercentInstance(...)");
        String text = percentInstance.format(i / 100.0d);
        Intrinsics.checkNotNullExpressionValue(text, "format(...)");
        Intrinsics.checkNotNullParameter(text, "text");
        SpannableStringBuilder spannableStringBuilder = new SpannableStringBuilder(text);
        int iL = StringsKt.L(text, '%', 0, false, 6);
        if (iL >= 0) {
            spannableStringBuilder.setSpan(new androidx.compose.ui.text.android.style.e(), iL, iL + 1, 33);
        }
        getHeaderScore().setText(spannableStringBuilder);
        getHeaderProgress().setProgress(i);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ArcProgressLayout(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public ArcProgressLayout(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        LayoutInflater.from(context).inflate(R.layout.view_arc_progress_layout, this);
        int i2 = R.id.arc_progress_bar;
        ArcProgressBar arcProgressBar = (ArcProgressBar) AbstractC3375o2.c(R.id.arc_progress_bar, this);
        if (arcProgressBar != null) {
            i2 = R.id.arc_progress_label;
            QTextView qTextView = (QTextView) AbstractC3375o2.c(R.id.arc_progress_label, this);
            if (qTextView != null) {
                i2 = R.id.arc_progress_value;
                QTextView qTextView2 = (QTextView) AbstractC3375o2.c(R.id.arc_progress_value, this);
                if (qTextView2 != null) {
                    f fVar = new f(this, arcProgressBar, qTextView, qTextView2, 11);
                    Intrinsics.checkNotNullExpressionValue(fVar, "inflate(...)");
                    this.a = fVar;
                    if (isInEditMode() || attributeSet == null) {
                        return;
                    }
                    int[] ArcProgressLayout = I.a;
                    Intrinsics.checkNotNullExpressionValue(ArcProgressLayout, "ArcProgressLayout");
                    TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, ArcProgressLayout, 0, 0);
                    getHeaderText().setText(typedArrayObtainStyledAttributes.getText(0));
                    typedArrayObtainStyledAttributes.recycle();
                    return;
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(i2)));
    }
}
