package com.quizlet.uicommon.ui.common.behaviors;

import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.widget.Space;
import androidx.coordinatorlayout.widget.CoordinatorLayout;
import androidx.coordinatorlayout.widget.b;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class TitleAnimateToToolbarBehavior extends b {
    public TitleAnimateToToolbarBehavior() {
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean f(CoordinatorLayout parent, View child, View dependency) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        Intrinsics.checkNotNullParameter(child, "child");
        Intrinsics.checkNotNullParameter(dependency, "dependency");
        return (dependency instanceof Space) && ((Space) dependency).getId() == R.id.titleSpace;
    }

    @Override // androidx.coordinatorlayout.widget.b
    public final boolean h(CoordinatorLayout parent, View child, View dependency) {
        View viewFindViewById;
        Intrinsics.checkNotNullParameter(parent, "parent");
        Intrinsics.checkNotNullParameter(child, "child");
        Intrinsics.checkNotNullParameter(dependency, "dependency");
        if (dependency.getId() == R.id.titleSpace && (viewFindViewById = parent.findViewById(R.id.toolbar_title)) != null) {
            if (dependency.getY() < child.getY() + child.getMeasuredHeight()) {
                viewFindViewById.setTranslationY(child.getMeasuredHeight() * (((dependency.getY() + dependency.getMeasuredHeight()) - (child.getY() + child.getMeasuredHeight())) / dependency.getMeasuredHeight()));
                return false;
            }
            viewFindViewById.setTranslationY(child.getMeasuredHeight());
        }
        return false;
    }

    public TitleAnimateToToolbarBehavior(@NotNull Context context, @NotNull AttributeSet attrs) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(attrs, "attrs");
    }
}
