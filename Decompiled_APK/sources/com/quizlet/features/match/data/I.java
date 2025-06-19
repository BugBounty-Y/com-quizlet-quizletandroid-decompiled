package com.quizlet.features.match.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class I extends O {
    public final com.quizlet.features.infra.snackbar.m a;

    public I(com.quizlet.features.infra.snackbar.m mVar) {
        this.a = mVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof I) && Intrinsics.b(this.a, ((I) obj).a);
    }

    public final int hashCode() {
        com.quizlet.features.infra.snackbar.m mVar = this.a;
        if (mVar == null) {
            return 0;
        }
        return mVar.hashCode();
    }

    public final String toString() {
        return "MatchNoShareData(toastData=" + this.a + ")";
    }
}
