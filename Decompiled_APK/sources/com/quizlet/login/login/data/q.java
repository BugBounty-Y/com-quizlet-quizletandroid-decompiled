package com.quizlet.login.login.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class q implements v {
    public final String a;
    public final String b;

    public q(String oauthState, String authProvider) {
        Intrinsics.checkNotNullParameter(oauthState, "oauthState");
        Intrinsics.checkNotNullParameter(authProvider, "authProvider");
        this.a = oauthState;
        this.b = authProvider;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof q)) {
            return false;
        }
        q qVar = (q) obj;
        return Intrinsics.b(this.a, qVar.a) && Intrinsics.b(this.b, qVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PromptForBirthday(oauthState=");
        sb.append(this.a);
        sb.append(", authProvider=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
