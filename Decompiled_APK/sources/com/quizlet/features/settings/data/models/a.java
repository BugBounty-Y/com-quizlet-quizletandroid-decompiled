package com.quizlet.features.settings.data.models;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final String b;
    public final String c;

    public a(String newPassword, String confirmPassword, String str) {
        Intrinsics.checkNotNullParameter(newPassword, "newPassword");
        Intrinsics.checkNotNullParameter(confirmPassword, "confirmPassword");
        this.a = newPassword;
        this.b = confirmPassword;
        this.c = str;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && Intrinsics.b(this.b, aVar.b) && Intrinsics.b(this.c, aVar.c);
    }

    public final int hashCode() {
        int iE = d0.e(this.a.hashCode() * 31, 31, this.b);
        String str = this.c;
        return iE + (str == null ? 0 : str.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ChangePasswordTuple(newPassword=");
        sb.append(this.a);
        sb.append(", confirmPassword=");
        sb.append(this.b);
        sb.append(", currentPassword=");
        return android.support.v4.media.session.a.t(sb, this.c, ")");
    }
}
