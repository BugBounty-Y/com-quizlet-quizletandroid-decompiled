package com.quizlet.features.setpage.header.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements h {
    public final com.quizlet.features.infra.models.b a;

    public f(com.quizlet.features.infra.models.b offlineStatus) {
        Intrinsics.checkNotNullParameter(offlineStatus, "offlineStatus");
        this.a = offlineStatus;
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
        return "Available(offlineStatus=" + this.a + ")";
    }
}
