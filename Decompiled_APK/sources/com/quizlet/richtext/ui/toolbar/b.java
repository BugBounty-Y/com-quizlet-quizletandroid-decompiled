package com.quizlet.richtext.ui.toolbar;

import android.widget.ToggleButton;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final ToggleButton a;
    public final c b;

    public b(ToggleButton button, c action) {
        Intrinsics.checkNotNullParameter(button, "button");
        Intrinsics.checkNotNullParameter(action, "action");
        this.a = button;
        this.b = action;
    }
}
