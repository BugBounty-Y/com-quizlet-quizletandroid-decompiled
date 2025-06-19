package com.quizlet.assembly.compose.buttons;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class X extends Y {
    public final String a;

    public X(String reason) {
        Intrinsics.checkNotNullParameter(reason, "reason");
        this.a = reason;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof X) && Intrinsics.b(this.a, ((X) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Stopped(reason="), this.a, ")");
    }
}
