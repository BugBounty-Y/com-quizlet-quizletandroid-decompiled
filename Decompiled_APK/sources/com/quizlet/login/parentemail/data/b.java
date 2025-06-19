package com.quizlet.login.parentemail.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements f {
    public final String a;
    public final String b;

    public b(String email, String password) {
        Intrinsics.checkNotNullParameter(email, "email");
        Intrinsics.checkNotNullParameter(password, "password");
        this.a = email;
        this.b = password;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof b)) {
            return false;
        }
        b bVar = (b) obj;
        return Intrinsics.b(this.a, bVar.a) && Intrinsics.b(this.b, bVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("CreateAccountClicked(email=");
        sb.append(this.a);
        sb.append(", password=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
