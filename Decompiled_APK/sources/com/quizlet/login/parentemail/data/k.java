package com.quizlet.login.parentemail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements n {
    public final String a;

    public k(String email) {
        Intrinsics.checkNotNullParameter(email, "email");
        this.a = email;
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
        return android.support.v4.media.session.a.t(new StringBuilder("MultipleAccountsFound(email="), this.a, ")");
    }
}
