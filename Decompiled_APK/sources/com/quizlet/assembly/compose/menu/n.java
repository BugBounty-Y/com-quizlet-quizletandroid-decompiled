package com.quizlet.assembly.compose.menu;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class n implements q {
    public final String a;

    public n(String text) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && Intrinsics.b(this.a, ((n) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("ContextTitle(text="), this.a, ")");
    }
}
