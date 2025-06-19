package com.quizlet.login.parentemail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o {
    public final boolean a;
    public final com.quizlet.login.authentication.k b;
    public final com.quizlet.login.common.interactors.data.j c;

    public o(boolean z, com.quizlet.login.authentication.k kVar, com.quizlet.login.common.interactors.data.j emailValidationResult) {
        Intrinsics.checkNotNullParameter(emailValidationResult, "emailValidationResult");
        this.a = z;
        this.b = kVar;
        this.c = emailValidationResult;
    }

    public static o a(o oVar, boolean z, com.quizlet.login.authentication.k kVar, com.quizlet.login.common.interactors.data.j emailValidationResult, int i) {
        if ((i & 1) != 0) {
            z = oVar.a;
        }
        if ((i & 2) != 0) {
            kVar = oVar.b;
        }
        if ((i & 4) != 0) {
            emailValidationResult = oVar.c;
        }
        oVar.getClass();
        Intrinsics.checkNotNullParameter(emailValidationResult, "emailValidationResult");
        return new o(z, kVar, emailValidationResult);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof o)) {
            return false;
        }
        o oVar = (o) obj;
        return this.a == oVar.a && Intrinsics.b(this.b, oVar.b) && Intrinsics.b(this.c, oVar.c);
    }

    public final int hashCode() {
        int iHashCode = Boolean.hashCode(this.a) * 31;
        com.quizlet.login.authentication.k kVar = this.b;
        return this.c.hashCode() + ((iHashCode + (kVar == null ? 0 : kVar.hashCode())) * 31);
    }

    public final String toString() {
        return "ParentEmailUiState(isLoading=" + this.a + ", authenticationError=" + this.b + ", emailValidationResult=" + this.c + ")";
    }
}
