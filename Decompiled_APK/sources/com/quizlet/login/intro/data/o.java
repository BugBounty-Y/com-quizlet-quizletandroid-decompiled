package com.quizlet.login.intro.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements t {
    public final String a;
    public final String b;

    public o(String oauthState, String authProvider) {
        Intrinsics.checkNotNullParameter(oauthState, "oauthState");
        Intrinsics.checkNotNullParameter(authProvider, "authProvider");
        this.a = oauthState;
        this.b = authProvider;
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
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PromptForBirthday(oauthState=");
        sb.append(this.a);
        sb.append(", authProvider=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
