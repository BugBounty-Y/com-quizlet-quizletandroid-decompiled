package com.quizlet.login.login.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class p implements v {
    public final String a;

    public p(String email) {
        Intrinsics.checkNotNullParameter(email, "email");
        this.a = email;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof p) && Intrinsics.b(this.a, ((p) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("MultipleAccountsFound(email="), this.a, ")");
    }
}
