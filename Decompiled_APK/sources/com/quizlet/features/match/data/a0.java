package com.quizlet.features.match.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a0 {
    public final double a;
    public final String b;
    public final String c;

    public a0(double d, String str, String str2) {
        this.a = d;
        this.b = str;
        this.c = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a0)) {
            return false;
        }
        a0 a0Var = (a0) obj;
        return Double.compare(this.a, a0Var.a) == 0 && Intrinsics.b(this.b, a0Var.b) && Intrinsics.b(this.c, a0Var.c);
    }

    public final int hashCode() {
        int iHashCode = Double.hashCode(this.a) * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        return iHashCode2 + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ShowChallengeEvent(scoreInSeconds=");
        sb.append(this.a);
        sb.append(", profileImageUrl=");
        sb.append(this.b);
        sb.append(", username=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
