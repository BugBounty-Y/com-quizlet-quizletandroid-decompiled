package com.quizlet.login.common.interactors.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u extends z {
    public final String a;
    public final String b;

    public u(String oauthState, String eventLoggerAuthProvider) {
        Intrinsics.checkNotNullParameter(oauthState, "oauthState");
        Intrinsics.checkNotNullParameter(eventLoggerAuthProvider, "eventLoggerAuthProvider");
        this.a = oauthState;
        this.b = eventLoggerAuthProvider;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof u)) {
            return false;
        }
        u uVar = (u) obj;
        return Intrinsics.b(this.a, uVar.a) && Intrinsics.b(this.b, uVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PromptForBirthday(oauthState=");
        sb.append(this.a);
        sb.append(", eventLoggerAuthProvider=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
