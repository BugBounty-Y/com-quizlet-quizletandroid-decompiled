package com.quizlet.quizletandroid.ui.common.ads;

import android.view.View;
import android.view.WindowManager;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.common.ads.b, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4635b {
    public final View a;
    public final WindowManager b;

    public C4635b(View adContainer, WindowManager windowManager) {
        Intrinsics.checkNotNullParameter(adContainer, "adContainer");
        Intrinsics.checkNotNullParameter(windowManager, "windowManager");
        this.a = adContainer;
        this.b = windowManager;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4635b)) {
            return false;
        }
        C4635b c4635b = (C4635b) obj;
        return Intrinsics.b(this.a, c4635b.a) && Intrinsics.b(this.b, c4635b.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "Input(adContainer=" + this.a + ", windowManager=" + this.b + ")";
    }
}
