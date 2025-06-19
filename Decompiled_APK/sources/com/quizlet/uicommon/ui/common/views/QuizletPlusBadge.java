package com.quizlet.uicommon.ui.common.views;

import android.content.Context;
import android.util.AttributeSet;
import com.quizlet.assembly.widgets.AssemblyPill;
import com.quizlet.assembly.widgets.c;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class QuizletPlusBadge extends AssemblyPill {
    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QuizletPlusBadge(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public QuizletPlusBadge(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public QuizletPlusBadge(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, 0);
        setVariant(c.d);
        setLeftImage(R.drawable.ic_sys_lock);
        setContentDescription(getResources().getString(R.string.quizlet_plus_locked_badge_a11y));
    }
}
