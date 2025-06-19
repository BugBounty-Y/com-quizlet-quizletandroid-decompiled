package com.quizlet.library.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class m implements p {
    public final kotlinx.collections.immutable.b a;

    public m(kotlinx.collections.immutable.b content) {
        Intrinsics.checkNotNullParameter(content, "content");
        this.a = content;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && Intrinsics.b(this.a, ((m) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Content(content=" + this.a + ")";
    }
}
