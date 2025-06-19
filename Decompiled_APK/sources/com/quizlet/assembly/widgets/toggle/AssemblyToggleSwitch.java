package com.quizlet.assembly.widgets.toggle;

import android.content.Context;
import android.util.AttributeSet;
import com.google.android.material.switchmaterial.a;
import com.quizlet.quizletandroid.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes2.dex */
public final class AssemblyToggleSwitch extends a {
    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyToggleSwitch(@NotNull Context context) {
        this(context, null, 6);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: 'this' call moved to the top of the method (can break code semantics) */
    public AssemblyToggleSwitch(@NotNull Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 4);
        Intrinsics.checkNotNullParameter(context, "context");
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public AssemblyToggleSwitch(Context context, AttributeSet attributeSet, int i) {
        attributeSet = (i & 2) != 0 ? null : attributeSet;
        Intrinsics.checkNotNullParameter(context, "context");
        super(context, attributeSet, R.attr.assemblyToggleSwitchStyle);
    }
}
