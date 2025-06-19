package com.quizlet.qutils.string;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final String a;

    public i(String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        this.a = string;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof i) {
            return Intrinsics.b(this.a, ((i) obj).a);
        }
        return false;
    }

    public final int hashCode() {
        return Integer.hashCode(1) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("StyledString(string="), this.a, ", style=1)");
    }
}
