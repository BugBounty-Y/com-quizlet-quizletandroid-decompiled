package com.quizlet.uicommon.ui.common.views;

import android.content.Context;
import android.content.res.Resources;
import android.util.AttributeSet;
import com.quizlet.assembly.widgets.AssemblyPill;
import com.quizlet.assembly.widgets.c;
import com.quizlet.partskit.widgets.QTextView;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletVerifiedBadge extends AssemblyPill {
    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QuizletVerifiedBadge(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QuizletVerifiedBadge(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public QuizletVerifiedBadge(Context context, AttributeSet attributeSet, int i) throws Resources.NotFoundException {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        setVariant(c.e);
        setLeftImage(2131231582);
        QTextView pillText = getBinding().c;
        Intrinsics.checkNotNullExpressionValue(pillText, "pillText");
        if (pillText.getVisibility() == 0) {
            return;
        }
        String string = getResources().getString(R.string.quizlet_verified_badge_a11y);
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        q(string);
    }
}
