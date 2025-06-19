package com.quizlet.features.emailconfirmation.ui.composables;

import androidx.compose.animation.d0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class r {
    public final String a;
    public final s b;
    public final boolean c;
    public final String d;
    public final String e;
    public final String f;

    public /* synthetic */ r(String str, s sVar, boolean z, String str2, String str3, int i) {
        this(str, sVar, (i & 4) != 0 ? false : z, str2, str3, (i & 32) != 0 ? null : "Log out");
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof r)) {
            return false;
        }
        r rVar = (r) obj;
        return Intrinsics.b(this.a, rVar.a) && this.b == rVar.b && this.c == rVar.c && Intrinsics.b(this.d, rVar.d) && Intrinsics.b(this.e, rVar.e) && Intrinsics.b(this.f, rVar.f);
    }

    public final int hashCode() {
        int iE = d0.e(d0.g((this.b.hashCode() + (this.a.hashCode() * 31)) * 31, 31, this.c), 31, this.d);
        String str = this.e;
        int iHashCode = (iE + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.f;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ConfirmYourEmailState(email=");
        sb.append(this.a);
        sb.append(", userType=");
        sb.append(this.b);
        sb.append(", hasExceededRequestLimit=");
        sb.append(this.c);
        sb.append(", primaryCTA=");
        sb.append(this.d);
        sb.append(", secondaryCTA=");
        sb.append(this.e);
        sb.append(", tertiaryCTA=");
        return android.support.v4.media.session.a.t(sb, this.f, ")");
    }

    public r(String email, s userType, boolean z, String primaryCTA, String str, String str2) {
        Intrinsics.checkNotNullParameter(email, "email");
        Intrinsics.checkNotNullParameter(userType, "userType");
        Intrinsics.checkNotNullParameter(primaryCTA, "primaryCTA");
        this.a = email;
        this.b = userType;
        this.c = z;
        this.d = primaryCTA;
        this.e = str;
        this.f = str2;
    }
}
