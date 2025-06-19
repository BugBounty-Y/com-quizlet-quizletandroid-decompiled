package com.quizlet.quizletandroid.ui.common.ads;

import android.view.View;
import android.view.WindowManager;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.common.ads.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4642i {
    public final View a;
    public final WindowManager b;
    public final com.quizlet.ads.c c;

    public C4642i(View view, WindowManager windowManager, com.quizlet.ads.c adUnit) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(windowManager, "windowManager");
        Intrinsics.checkNotNullParameter(adUnit, "adUnit");
        this.a = view;
        this.b = windowManager;
        this.c = adUnit;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4642i)) {
            return false;
        }
        C4642i c4642i = (C4642i) obj;
        return Intrinsics.b(this.a, c4642i.a) && Intrinsics.b(this.b, c4642i.b) && this.c == c4642i.c;
    }

    public final int hashCode() {
        return this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        return "Input(view=" + this.a + ", windowManager=" + this.b + ", adUnit=" + this.c + ")";
    }
}
