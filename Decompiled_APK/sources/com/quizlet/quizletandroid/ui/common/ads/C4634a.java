package com.quizlet.quizletandroid.ui.common.ads;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.quizletandroid.ui.common.ads.a, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4634a {
    public final com.quizlet.ads.c a;
    public final String b;
    public final boolean c;
    public final boolean d;
    public final boolean e;

    public C4634a(com.quizlet.ads.c adUnit, String str, boolean z, boolean z2, boolean z3) {
        Intrinsics.checkNotNullParameter(adUnit, "adUnit");
        this.a = adUnit;
        this.b = str;
        this.c = z;
        this.d = z2;
        this.e = z3;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4634a)) {
            return false;
        }
        C4634a c4634a = (C4634a) obj;
        return this.a == c4634a.a && Intrinsics.b(this.b, c4634a.b) && this.c == c4634a.c && this.d == c4634a.d && this.e == c4634a.e;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return Boolean.hashCode(this.e) + d0.g(d0.g((iHashCode + (str == null ? 0 : str.hashCode())) * 31, 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("AdMetadata(adUnit=");
        sb.append(this.a);
        sb.append(", contentWebUrl=");
        sb.append(this.b);
        sb.append(", isEligibleForAds=");
        sb.append(this.c);
        sb.append(", shouldTagForChildDirectedTreatment=");
        sb.append(this.d);
        sb.append(", isConnected=");
        return android.support.v4.media.session.a.o(")", sb, this.e);
    }
}
