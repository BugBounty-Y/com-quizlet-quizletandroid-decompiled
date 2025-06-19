package com.quizlet.login.signup.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements h {
    public final long a;
    public final String b;
    public final String c;
    public final boolean d;

    public c(long j, String email, String password, boolean z) {
        Intrinsics.checkNotNullParameter(email, "email");
        Intrinsics.checkNotNullParameter(password, "password");
        this.a = j;
        this.b = email;
        this.c = password;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return this.a == cVar.a && Intrinsics.b(this.b, cVar.b) && Intrinsics.b(this.c, cVar.c) && this.d == cVar.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.e(d0.e(Long.hashCode(this.a) * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CreateAccountButtonClicked(birthday=");
        sb.append(this.a);
        sb.append(", email=");
        sb.append(this.b);
        sb.append(", password=");
        sb.append(this.c);
        sb.append(", isStudent=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
