package com.quizlet.themes;

import android.content.Context;
import android.view.View;
import androidx.compose.runtime.C0776c;
import androidx.compose.runtime.H0;
import androidx.compose.ui.platform.ViewTreeObserverOnGlobalLayoutListenerC0944h;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* loaded from: classes3.dex */
public final class q extends View {
    public static final /* synthetic */ int b = 0;
    public final H0 a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public q(@NotNull Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
        this.a = C0776c.w(0);
        getViewTreeObserver().addOnGlobalLayoutListener(new ViewTreeObserverOnGlobalLayoutListenerC0944h(this, 3));
    }

    public final int getKeyboardHeight() {
        return this.a.i();
    }

    public final void setKeyboardHeight(int i) {
        this.a.j(i);
    }
}
