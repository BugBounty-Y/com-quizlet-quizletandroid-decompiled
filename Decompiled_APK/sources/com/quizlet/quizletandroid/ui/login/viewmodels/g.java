package com.quizlet.quizletandroid.ui.login.viewmodels;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g {
    public final String a;
    public final String b;

    public g(String email, String str) {
        Intrinsics.checkNotNullParameter(email, "email");
        this.a = email;
        this.b = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof g)) {
            return false;
        }
        g gVar = (g) obj;
        return Intrinsics.b(this.a, gVar.a) && Intrinsics.b(this.b, gVar.b);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ParentSignUpEvent(email=");
        sb.append(this.a);
        sb.append(", password=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
