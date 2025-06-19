package com.quizlet.quizletandroid.ui.common.ads;

import android.content.Context;
import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.common.ads.g, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4640g {
    public final Context a;
    public final String b;
    public final com.google.android.gms.ads.h c;

    public C4640g(Context context, String adUnitName, com.google.android.gms.ads.h adSize) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(adUnitName, "adUnitName");
        Intrinsics.checkNotNullParameter(adSize, "adSize");
        this.a = context;
        this.b = adUnitName;
        this.c = adSize;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4640g)) {
            return false;
        }
        C4640g c4640g = (C4640g) obj;
        return Intrinsics.b(this.a, c4640g.a) && Intrinsics.b(this.b, c4640g.b) && Intrinsics.b(this.c, c4640g.c);
    }

    public final int hashCode() {
        return this.c.c.hashCode() + d0.e(this.a.hashCode() * 31, 31, this.b);
    }

    public final String toString() {
        return "Input(context=" + this.a + ", adUnitName=" + this.b + ", adSize=" + this.c + ")";
    }
}
