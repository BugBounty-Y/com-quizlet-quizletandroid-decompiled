package com.quizlet.library.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f extends i {
    public final kotlinx.collections.immutable.b a;

    public f(kotlinx.collections.immutable.b content) {
        Intrinsics.checkNotNullParameter(content, "content");
        this.a = content;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && Intrinsics.b(this.a, ((f) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Content(content=" + this.a + ")";
    }
}
