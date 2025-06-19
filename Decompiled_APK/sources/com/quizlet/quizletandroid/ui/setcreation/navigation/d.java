package com.quizlet.quizletandroid.ui.setcreation.navigation;

import com.quizlet.quizletandroid.ui.globalnav.composable.n;
import com.quizlet.qutils.string.f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends e {
    public final f a;
    public final f b;
    public final f c;
    public final n d;
    public final n e;

    public d(f titleResId, f positiveButtonTitle, f negativeButtonTitle, n positiveClickCallback, n negativeClickCallback) {
        Intrinsics.checkNotNullParameter(titleResId, "titleResId");
        Intrinsics.checkNotNullParameter(positiveButtonTitle, "positiveButtonTitle");
        Intrinsics.checkNotNullParameter(negativeButtonTitle, "negativeButtonTitle");
        Intrinsics.checkNotNullParameter(positiveClickCallback, "positiveClickCallback");
        Intrinsics.checkNotNullParameter(negativeClickCallback, "negativeClickCallback");
        this.a = titleResId;
        this.b = positiveButtonTitle;
        this.c = negativeButtonTitle;
        this.d = positiveClickCallback;
        this.e = negativeClickCallback;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof d)) {
            return false;
        }
        d dVar = (d) obj;
        return this.a.equals(dVar.a) && this.b.equals(dVar.b) && this.c.equals(dVar.c) && this.d.equals(dVar.d) && this.e.equals(dVar.e);
    }

    public final int hashCode() {
        return this.e.hashCode() + ((this.d.hashCode() + ((this.c.hashCode() + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31)) * 31)) * 31);
    }

    public final String toString() {
        return "ShowU13SetCreationDialog(titleResId=" + this.a + ", positiveButtonTitle=" + this.b + ", negativeButtonTitle=" + this.c + ", positiveClickCallback=" + this.d + ", negativeClickCallback=" + this.e + ")";
    }
}
