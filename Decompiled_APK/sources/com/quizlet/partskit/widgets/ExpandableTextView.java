package com.quizlet.partskit.widgets;

import android.animation.TimeInterpolator;
import android.content.Context;
import android.content.res.TypedArray;
import android.util.AttributeSet;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import com.quizlet.themes.u;
import java.util.ArrayList;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ExpandableTextView extends QTextView {
    public int a;
    public TimeInterpolator b;
    public TimeInterpolator c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ExpandableTextView(@NotNull Context context, AttributeSet attributeSet) {
        super(context, attributeSet, 0);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(context, "context");
        new ArrayList();
        this.b = new AccelerateDecelerateInterpolator();
        this.c = new AccelerateDecelerateInterpolator();
        TypedArray typedArrayObtainStyledAttributes = context.obtainStyledAttributes(attributeSet, u.a, 0, 0);
        Intrinsics.checkNotNullExpressionValue(typedArrayObtainStyledAttributes, "obtainStyledAttributes(...)");
        typedArrayObtainStyledAttributes.getInt(0, 250);
        typedArrayObtainStyledAttributes.recycle();
        this.a = getMaxLines();
    }

    @NotNull
    public final TimeInterpolator getCollapseInterpolator() {
        return this.c;
    }

    @NotNull
    public final TimeInterpolator getExpandInterpolator() {
        return this.b;
    }

    @Override // androidx.appcompat.widget.AppCompatTextView, android.widget.TextView, android.view.View
    public final void onMeasure(int i, int i2) {
        if (this.a == 0) {
            i2 = View.MeasureSpec.makeMeasureSpec(0, 1073741824);
        }
        super.onMeasure(i, i2);
    }

    public final void setAnimationDuration(long j) {
    }

    public final void setCollapseInterpolator(@NotNull TimeInterpolator timeInterpolator) {
        Intrinsics.checkNotNullParameter(timeInterpolator, "<set-?>");
        this.c = timeInterpolator;
    }

    public final void setExpandInterpolator(@NotNull TimeInterpolator timeInterpolator) {
        Intrinsics.checkNotNullParameter(timeInterpolator, "<set-?>");
        this.b = timeInterpolator;
    }

    public final void setInterpolator(@NotNull TimeInterpolator interpolator) {
        Intrinsics.checkNotNullParameter(interpolator, "interpolator");
        this.b = interpolator;
        this.c = interpolator;
    }

    public final void setOriginalMaxLines(int i) {
        this.a = i;
        setMaxLines(i);
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public ExpandableTextView(@NotNull Context context) {
        this(context, null);
        Intrinsics.checkNotNullParameter(context, "context");
    }
}
