package com.quizlet.features.questionnaire.navigation;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class n extends q {
    public final String a;
    public final String b;

    public n(String payload, String str) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.a = payload;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof n)) {
            return false;
        }
        n nVar = (n) obj;
        return Intrinsics.b(this.a, nVar.a) && Intrinsics.b(this.b, nVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExamsSelected(payload=");
        sb.append(this.a);
        sb.append(", nextStep=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
