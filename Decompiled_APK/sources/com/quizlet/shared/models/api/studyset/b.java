package com.quizlet.shared.models.api.studyset;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b {
    public final String a;

    public b(String setId) {
        Intrinsics.checkNotNullParameter(setId, "setId");
        this.a = setId;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && Intrinsics.b(this.a, ((b) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("TermRequest(setId="), this.a, ")");
    }
}
