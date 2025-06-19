package com.quizlet.login.resetpassword.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final boolean a;
    public final com.quizlet.qutils.string.f b;

    public g(com.quizlet.qutils.string.f fVar, boolean z) {
        this.a = z;
        this.b = fVar;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return this.a == gVar.a && Intrinsics.b(this.b, gVar.b);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        com.quizlet.qutils.string.f fVar = this.b;
        return iHashCode + (fVar == null ? 0 : fVar.hashCode());
    }

    public final String toString() {
        return "ResetPasswordUiState(isLoading=" + this.a + ", error=" + this.b + ")";
    }
}
