package com.quizlet.login.magiclink.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements k {
    public final g a;

    public h(g type) {
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = type;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof h) && Intrinsics.b(this.a, ((h) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Error(type=" + this.a + ")";
    }
}
