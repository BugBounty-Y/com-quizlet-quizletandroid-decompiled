package com.quizlet.partskit.widgets.icon;

import android.content.Context;
import android.util.AttributeSet;
import android.view.accessibility.AccessibilityNodeInfo;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QStarIconView extends IconFontTextView {
    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QStarIconView(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    @Override // com.quizlet.partskit.widgets.icon.IconFontTextView, android.view.View
    public final void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        Intrinsics.checkNotNullParameter(info, "info");
        super.onInitializeAccessibilityNodeInfo(info);
        info.setSelected(false);
    }

    @Override // android.widget.TextView, android.view.View
    public void setSelected(boolean z) {
        super.setSelected(z);
        setIcon(z ? "star" : "star-empty");
        setContentDescription(z ? getResources().getString(R.string.icon_label_star) : getResources().getString(R.string.icon_label_no_star));
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QStarIconView(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public QStarIconView(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        if (isInEditMode()) {
            return;
        }
        setIcon("star-empty");
        setTextColor(com.quizlet.themes.extensions.a.a(context, R.attr.colorControlEnabled));
    }
}
