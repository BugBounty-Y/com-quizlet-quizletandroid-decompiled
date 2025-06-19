package com.quizlet.features.questionnaire.navigation;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o extends q {
    public final String a;
    public final String b;

    public o(String payload, String str) {
        Intrinsics.checkNotNullParameter(payload, "payload");
        this.a = payload;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return Intrinsics.b(this.a, oVar.a) && Intrinsics.b(this.b, oVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("IntroSelected(payload=");
        sb.append(this.a);
        sb.append(", nextStep=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
