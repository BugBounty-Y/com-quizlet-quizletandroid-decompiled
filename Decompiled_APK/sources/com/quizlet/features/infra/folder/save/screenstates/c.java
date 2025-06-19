package com.quizlet.features.infra.folder.save.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements d {
    public final a a;

    public c(a addState) {
        Intrinsics.checkNotNullParameter(addState, "addState");
        this.a = addState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && this.a == ((c) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Loaded(addState=" + this.a + ")";
    }
}
