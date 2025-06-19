package com.quizlet.upgrade.ui.widgets;

import android.content.Context;
import android.util.AttributeSet;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import androidx.constraintlayout.widget.ConstraintLayout;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3375o2;
import com.quizlet.features.infra.legacyadapter.databinding.h;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class UpgradeTimelineSectionLayout extends ConstraintLayout {
    public final h q;

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public UpgradeTimelineSectionLayout(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public UpgradeTimelineSectionLayout(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public UpgradeTimelineSectionLayout(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        LayoutInflater.from(context).inflate(R.layout.view_upgrade_timeline_section_layout, this);
        int i2 = R.id.header;
        TextView textView = (TextView) AbstractC3375o2.c(R.id.header, this);
        if (textView != null) {
            i2 = R.id.icon;
            ImageView imageView = (ImageView) AbstractC3375o2.c(R.id.icon, this);
            if (imageView != null) {
                i2 = R.id.info;
                TextView textView2 = (TextView) AbstractC3375o2.c(R.id.info, this);
                if (textView2 != null) {
                    i2 = R.id.line;
                    View viewC = AbstractC3375o2.c(R.id.line, this);
                    if (viewC != null) {
                        h hVar = new h(this, textView, imageView, textView2, viewC, 5);
                        Intrinsics.checkNotNullExpressionValue(hVar, "inflate(...)");
                        this.q = hVar;
                        return;
                    }
                }
            }
        }
        throw new NullPointerException("Missing required view with ID: ".concat(getResources().getResourceName(i2)));
    }
}
