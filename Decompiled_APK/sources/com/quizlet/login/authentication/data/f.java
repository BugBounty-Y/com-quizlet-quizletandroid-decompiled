package com.quizlet.login.authentication.data;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f {
    public final String a;
    public final String b;
    public final String c;
    public final boolean d;

    public f(String username, String email, String str, boolean z) {
        Intrinsics.checkNotNullParameter(username, "username");
        Intrinsics.checkNotNullParameter(email, "email");
        this.a = username;
        this.b = email;
        this.c = str;
        this.d = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof f)) {
            return false;
        }
        f fVar = (f) obj;
        return Intrinsics.b(this.a, fVar.a) && Intrinsics.b(this.b, fVar.b) && Intrinsics.b(this.c, fVar.c) && this.d == fVar.d;
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return Boolean.hashCode(this.d) + ((iE + (str == null ? 0 : str.hashCode())) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ExistingAccountInfo(username=");
        sb.append(this.a);
        sb.append(", email=");
        sb.append(this.b);
        sb.append(", profileImageUrl=");
        sb.append(this.c);
        sb.append(", isUserPlus=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }
}
