package com.quizlet.login.authentication;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b extends k {
    public final String c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public b(String string) {
        super(new com.quizlet.qutils.string.e(string), null, 6);
        Intrinsics.checkNotNullParameter(string, "message");
        Intrinsics.checkNotNullParameter(string, "string");
        this.c = string;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.c, ((b) obj).c);
    }

    public final int hashCode() {
        return this.c.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("ApiThree(message="), this.c, ")");
    }
}
