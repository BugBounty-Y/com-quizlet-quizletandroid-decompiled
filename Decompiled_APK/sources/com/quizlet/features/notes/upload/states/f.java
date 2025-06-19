package com.quizlet.features.notes.upload.states;

import com.quizlet.data.model.m2;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements h {
    public final m2 a;

    public f(m2 source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && this.a == ((f) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "CreatingMagicNotes(source=" + this.a + ")";
    }
}
