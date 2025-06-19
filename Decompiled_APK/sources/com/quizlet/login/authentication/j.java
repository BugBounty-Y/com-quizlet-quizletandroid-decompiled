package com.quizlet.login.authentication;

import com.quizlet.quizletandroid.R;
import kotlin.collections.C4933y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class j extends k {
    public final String c;

    /* JADX WARN: Illegal instructions before constructor call */
    public j(String username) {
        Intrinsics.checkNotNullParameter(username, "username");
        Object[] args = {username};
        Intrinsics.checkNotNullParameter(args, "args");
        super(new com.quizlet.qutils.string.f(R.string.login_username_not_found, C4933y.P(args)), null, 6);
        this.c = username;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof j) && Intrinsics.b(this.c, ((j) obj).c);
    }

    public final int hashCode() {
        return this.c.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("UsernameNotFound(username="), this.c, ")");
    }
}
