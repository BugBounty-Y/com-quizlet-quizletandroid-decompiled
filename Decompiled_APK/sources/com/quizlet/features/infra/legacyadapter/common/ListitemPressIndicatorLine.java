package com.quizlet.features.infra.legacyadapter.common;

import android.content.Context;
import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.StateListDrawable;
import android.util.AttributeSet;
import android.util.StateSet;
import android.view.View;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class ListitemPressIndicatorLine extends View {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ListitemPressIndicatorLine(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        a(context);
    }

    public final void a(Context context) {
        ColorDrawable colorDrawable = new ColorDrawable(com.quizlet.themes.extensions.a.a(context, R.attr.Transparent));
        Intrinsics.checkNotNullParameter(context, "<this>");
        ColorDrawable colorDrawable2 = new ColorDrawable(com.quizlet.themes.extensions.a.a(context, R.attr.stateActivated));
        ColorDrawable colorDrawable3 = new ColorDrawable(com.quizlet.themes.extensions.a.a(context, R.attr.stateDisabled));
        StateListDrawable stateListDrawable = new StateListDrawable();
        stateListDrawable.addState(new int[]{android.R.attr.state_pressed}, colorDrawable2);
        stateListDrawable.addState(new int[]{android.R.attr.state_selected}, colorDrawable2);
        stateListDrawable.addState(new int[]{android.R.attr.state_focused}, colorDrawable2);
        stateListDrawable.addState(new int[]{-16842910}, colorDrawable3);
        stateListDrawable.addState(StateSet.WILD_CARD, colorDrawable);
        stateListDrawable.setEnterFadeDuration(context.getResources().getInteger(R.integer.animation_duration_standard));
        stateListDrawable.setExitFadeDuration(context.getResources().getInteger(R.integer.animation_duration_standard));
        setBackground(stateListDrawable);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ListitemPressIndicatorLine(@NotNull Context context, @NotNull AttributeSet attrSet) {
        super(context, attrSet);
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attrSet, "attrSet");
        a(context);
    }
}
