package com.quizlet.login.login.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class w {
    public final com.quizlet.login.authentication.k a;
    public final boolean b;
    public final boolean c;
    public final boolean d;
    public final String e;

    public w(com.quizlet.login.authentication.k kVar, boolean z, boolean z2, boolean z3, String email) {
        Intrinsics.checkNotNullParameter(email, "email");
        this.a = kVar;
        this.b = z;
        this.c = z2;
        this.d = z3;
        this.e = email;
    }

    public static w a(w wVar, com.quizlet.login.authentication.k kVar, boolean z, boolean z2, boolean z3, String str, int i) {
        if ((i & 1) != 0) {
            kVar = wVar.a;
        }
        com.quizlet.login.authentication.k kVar2 = kVar;
        if ((i & 2) != 0) {
            z = wVar.b;
        }
        boolean z4 = z;
        if ((i & 4) != 0) {
            z2 = wVar.c;
        }
        boolean z5 = z2;
        if ((i & 8) != 0) {
            z3 = wVar.d;
        }
        boolean z6 = z3;
        if ((i & 16) != 0) {
            str = wVar.e;
        }
        String email = str;
        wVar.getClass();
        Intrinsics.checkNotNullParameter(email, "email");
        return new w(kVar2, z4, z5, z6, email);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof w)) {
            return false;
        }
        w wVar = (w) obj;
        return Intrinsics.b(this.a, wVar.a) && this.b == wVar.b && this.c == wVar.c && this.d == wVar.d && Intrinsics.b(this.e, wVar.e);
    }

    public final int hashCode() {
        com.quizlet.login.authentication.k kVar = this.a;
        return this.e.hashCode() + d0.g(d0.g(d0.g((kVar == null ? 0 : kVar.hashCode()) * 31, 31, this.b), 31, this.c), 31, this.d);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LoginUiState(authenticationError=");
        sb.append(this.a);
        sb.append(", shouldShowAuthenticationErrorDialog=");
        sb.append(this.b);
        sb.append(", isLoading=");
        sb.append(this.c);
        sb.append(", isFacebookButtonVisible=");
        sb.append(this.d);
        sb.append(", email=");
        return android.support.v4.media.session.a.t(sb, this.e, ")");
    }
}
