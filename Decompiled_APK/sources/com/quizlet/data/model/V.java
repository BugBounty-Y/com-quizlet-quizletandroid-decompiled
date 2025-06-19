package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class V {
    public final String a;
    public final String b;
    public final String c;
    public final String d;

    public V(String experimentKey, String variantId, String str, String str2) {
        Intrinsics.checkNotNullParameter(experimentKey, "experimentKey");
        Intrinsics.checkNotNullParameter(variantId, "variantId");
        this.a = experimentKey;
        this.b = variantId;
        this.c = str;
        this.d = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof V)) {
            return false;
        }
        V v = (V) obj;
        return Intrinsics.b(this.a, v.a) && Intrinsics.b(this.b, v.b) && Intrinsics.b(this.c, v.c) && Intrinsics.b(this.d, v.d);
    }

    public final int hashCode() {
        int iE = androidx.compose.animation.d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.d;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExperimentEnrollmentData(experimentKey=");
        sb.append(this.a);
        sb.append(", variantId=");
        sb.append(this.b);
        sb.append(", hashAttribute=");
        sb.append(this.c);
        sb.append(", hashValue=");
        return android.support.v4.media.session.a.t(sb, this.d, ")");
    }
}
