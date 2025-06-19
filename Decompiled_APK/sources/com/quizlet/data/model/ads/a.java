package com.quizlet.data.model.ads;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a implements c {
    public final Exception a;

    public a(Exception error) {
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
        return "Failure(error=" + this.a + ")";
    }
}
