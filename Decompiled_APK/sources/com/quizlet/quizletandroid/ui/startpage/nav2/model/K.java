package com.quizlet.quizletandroid.ui.startpage.nav2.model;

import android.view.View;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class K {
    public final View a;

    public K(View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        this.a = view;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof K) && Intrinsics.b(this.a, ((K) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "RateUsViewReference(view=" + this.a + ")";
    }
}
