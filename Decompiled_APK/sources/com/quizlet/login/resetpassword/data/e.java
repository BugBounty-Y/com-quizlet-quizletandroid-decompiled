package com.quizlet.login.resetpassword.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements f {
    public final String a;

    public e(String email) {
        Intrinsics.checkNotNullParameter(email, "email");
        this.a = email;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof e) && Intrinsics.b(this.a, ((e) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("EmailSent(email="), this.a, ")");
    }
}
