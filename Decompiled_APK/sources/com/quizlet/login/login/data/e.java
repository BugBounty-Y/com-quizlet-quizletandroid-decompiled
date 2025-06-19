package com.quizlet.login.login.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements k {
    public final String a;
    public final String b;

    public e(String email, String password) {
        Intrinsics.checkNotNullParameter(email, "email");
        Intrinsics.checkNotNullParameter(password, "password");
        this.a = email;
        this.b = password;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof e)) {
            return false;
        }
        e eVar = (e) obj;
        return Intrinsics.b(this.a, eVar.a) && Intrinsics.b(this.b, eVar.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("LogInButtonClicked(email=");
        sb.append(this.a);
        sb.append(", password=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
