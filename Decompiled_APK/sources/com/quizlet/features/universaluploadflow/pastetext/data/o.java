package com.quizlet.features.universaluploadflow.pastetext.data;

import com.quizlet.data.model.m2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements p {
    public final m2 a;

    public o(m2 source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof o) && this.a == ((o) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "GeneratingContent(source=" + this.a + ")";
    }
}
