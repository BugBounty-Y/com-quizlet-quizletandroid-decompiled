package com.quizlet.quizletandroid.ui.login.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h {
    public final d a;
    public final d b;

    public h(d emailValidation, d passwordValidation) {
        Intrinsics.checkNotNullParameter(emailValidation, "emailValidation");
        Intrinsics.checkNotNullParameter(passwordValidation, "passwordValidation");
        this.a = emailValidation;
        this.b = passwordValidation;
    }

    public static h a(h hVar, d emailValidation, d passwordValidation, int i) {
        if ((i & 1) != 0) {
            emailValidation = hVar.a;
        }
        if ((i & 2) != 0) {
            passwordValidation = hVar.b;
        }
        hVar.getClass();
        Intrinsics.checkNotNullParameter(emailValidation, "emailValidation");
        Intrinsics.checkNotNullParameter(passwordValidation, "passwordValidation");
        return new h(emailValidation, passwordValidation);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return Intrinsics.b(this.a, hVar.a) && Intrinsics.b(this.b, hVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "ParentSignUpValidation(emailValidation=" + this.a + ", passwordValidation=" + this.b + ")";
    }
}
