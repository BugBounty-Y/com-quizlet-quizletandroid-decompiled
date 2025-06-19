package com.quizlet.diagrams.ui;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class j extends l {
    public final String a;

    public j(String diagramDataString) {
        Intrinsics.checkNotNullParameter(diagramDataString, "diagramDataString");
        this.a = diagramDataString;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof j) && Intrinsics.b(this.a, ((j) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("Loaded(diagramDataString="), this.a, ")");
    }
}
