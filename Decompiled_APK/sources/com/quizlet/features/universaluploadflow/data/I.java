package com.quizlet.features.universaluploadflow.data;

import com.quizlet.data.model.m2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class I implements K {
    public final m2 a;

    public I(m2 source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
    }

    @Override // com.quizlet.features.universaluploadflow.data.K
    public final boolean a() {
        return false;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof I) && this.a == ((I) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "GeneratingContent(source=" + this.a + ")";
    }
}
