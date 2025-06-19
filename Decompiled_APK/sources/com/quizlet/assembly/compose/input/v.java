package com.quizlet.assembly.compose.input;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class v implements w {
    public final String a;

    public v(String text) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof v) && Intrinsics.b(this.a, ((v) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Text(text="), this.a, ")");
    }
}
