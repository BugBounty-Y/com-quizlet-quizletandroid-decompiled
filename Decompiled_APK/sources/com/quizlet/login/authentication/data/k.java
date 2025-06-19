package com.quizlet.login.authentication.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k extends i {
    public final String a;

    public k(String oauthState) {
        Intrinsics.checkNotNullParameter(oauthState, "oauthState");
        this.a = oauthState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof k) && Intrinsics.b(this.a, ((k) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PromptForBirthday(oauthState="), this.a, ")");
    }
}
