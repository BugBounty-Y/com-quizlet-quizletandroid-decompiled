package com.quizlet.login.signup.data;

import androidx.compose.animation.d0;
import com.quizlet.login.common.interactors.data.C4590a;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r {
    public final boolean a;
    public final C4590a b;
    public final boolean c;
    public final com.quizlet.login.authentication.k d;
    public final com.quizlet.login.common.interactors.data.j e;
    public final com.quizlet.login.common.interactors.data.d f;

    public r(boolean z, C4590a calendarDate, boolean z2, com.quizlet.login.authentication.k kVar, com.quizlet.login.common.interactors.data.j emailValidationResult, com.quizlet.login.common.interactors.data.d dateOfBirthResult) {
        Intrinsics.checkNotNullParameter(calendarDate, "calendarDate");
        Intrinsics.checkNotNullParameter(emailValidationResult, "emailValidationResult");
        Intrinsics.checkNotNullParameter(dateOfBirthResult, "dateOfBirthResult");
        this.a = z;
        this.b = calendarDate;
        this.c = z2;
        this.d = kVar;
        this.e = emailValidationResult;
        this.f = dateOfBirthResult;
    }

    public static r a(r rVar, boolean z, boolean z2, com.quizlet.login.authentication.k kVar, com.quizlet.login.common.interactors.data.j jVar, com.quizlet.login.common.interactors.data.d dVar, int i) {
        if ((i & 1) != 0) {
            z = rVar.a;
        }
        boolean z3 = z;
        C4590a calendarDate = rVar.b;
        if ((i & 4) != 0) {
            z2 = rVar.c;
        }
        boolean z4 = z2;
        if ((i & 8) != 0) {
            kVar = rVar.d;
        }
        com.quizlet.login.authentication.k kVar2 = kVar;
        if ((i & 16) != 0) {
            jVar = rVar.e;
        }
        com.quizlet.login.common.interactors.data.j emailValidationResult = jVar;
        if ((i & 32) != 0) {
            dVar = rVar.f;
        }
        com.quizlet.login.common.interactors.data.d dateOfBirthResult = dVar;
        rVar.getClass();
        Intrinsics.checkNotNullParameter(calendarDate, "calendarDate");
        Intrinsics.checkNotNullParameter(emailValidationResult, "emailValidationResult");
        Intrinsics.checkNotNullParameter(dateOfBirthResult, "dateOfBirthResult");
        return new r(z3, calendarDate, z4, kVar2, emailValidationResult, dateOfBirthResult);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return this.a == rVar.a && Intrinsics.b(this.b, rVar.b) && this.c == rVar.c && Intrinsics.b(this.d, rVar.d) && Intrinsics.b(this.e, rVar.e) && Intrinsics.b(this.f, rVar.f);
    }

    public final int hashCode() {
        int iG = d0.g((this.b.hashCode() + (Boolean.hashCode(this.a) * 31)) * 31, 31, this.c);
        com.quizlet.login.authentication.k kVar = this.d;
        return this.f.hashCode() + ((this.e.hashCode() + ((iG + (kVar == null ? 0 : kVar.hashCode())) * 31)) * 31);
    }

    public final String toString() {
        return "SignUpUiState(isLoading=" + this.a + ", calendarDate=" + this.b + ", isUserTypeVisible=" + this.c + ", authenticationError=" + this.d + ", emailValidationResult=" + this.e + ", dateOfBirthResult=" + this.f + ")";
    }
}
