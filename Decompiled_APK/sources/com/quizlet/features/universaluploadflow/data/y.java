package com.quizlet.features.universaluploadflow.data;

import com.quizlet.data.model.m2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class y implements F {
    public final m2 a;

    public y(m2 source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof y) && this.a == ((y) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Login(source=" + this.a + ")";
    }
}
