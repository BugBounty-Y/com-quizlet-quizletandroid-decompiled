package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class N0 implements O0 {
    public final String a;
    public final String b;

    public N0(String destination, String questionBankId) {
        Intrinsics.checkNotNullParameter(destination, "destination");
        Intrinsics.checkNotNullParameter(questionBankId, "questionBankId");
        this.a = destination;
        this.b = questionBankId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof N0)) {
            return false;
        }
        N0 n0 = (N0) obj;
        return Intrinsics.b(this.a, n0.a) && Intrinsics.b(this.b, n0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Redirect(destination=");
        sb.append(this.a);
        sb.append(", questionBankId=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
