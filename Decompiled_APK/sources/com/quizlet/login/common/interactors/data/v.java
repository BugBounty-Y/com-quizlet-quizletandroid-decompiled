package com.quizlet.login.common.interactors.data;

import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class v extends z {
    public final Map a;

    public v(Map requestParams) {
        com.quizlet.login.oldlogin.b requestType = com.quizlet.login.oldlogin.b.b;
        Intrinsics.checkNotNullParameter(requestParams, "requestParams");
        Intrinsics.checkNotNullParameter("email", "authProvider");
        Intrinsics.checkNotNullParameter(requestType, "requestType");
        this.a = requestParams;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof v)) {
            return false;
        }
        if (!Intrinsics.b(this.a, ((v) obj).a)) {
            return false;
        }
        com.quizlet.login.oldlogin.b bVar = com.quizlet.login.oldlogin.b.a;
        return true;
    }

    public final int hashCode() {
        return com.quizlet.login.oldlogin.b.b.hashCode() + (((this.a.hashCode() * 31) + 96619420) * 31);
    }

    public final String toString() {
        return "PromptParentEmail(requestParams=" + this.a + ", authProvider=email, requestType=" + com.quizlet.login.oldlogin.b.b + ")";
    }
}
