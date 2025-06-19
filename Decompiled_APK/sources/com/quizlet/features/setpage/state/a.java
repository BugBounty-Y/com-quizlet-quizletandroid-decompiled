package com.quizlet.features.setpage.state;

import com.quizlet.qutils.string.f;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends d {
    public final f a;

    public a(f error) {
        Intrinsics.checkNotNullParameter(error, "error");
        this.a = error;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && this.a.equals(((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Error(error=" + this.a + ")";
    }
}
