package com.quizlet.features.emailconfirmation.data.states;

import com.quizlet.features.emailconfirmation.ui.composables.s;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a {
    public final String a;
    public final s b;
    public final boolean c;

    public a(String email, s userType, boolean z) {
        Intrinsics.checkNotNullParameter(email, "email");
        Intrinsics.checkNotNullParameter(userType, "userType");
        this.a = email;
        this.b = userType;
        this.c = z;
    }

    public static a a(a aVar, String email, s userType, int i) {
        if ((i & 1) != 0) {
            email = aVar.a;
        }
        if ((i & 2) != 0) {
            userType = aVar.b;
        }
        boolean z = (i & 4) != 0 ? aVar.c : true;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(email, "email");
        Intrinsics.checkNotNullParameter(userType, "userType");
        return new a(email, userType, z);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return Intrinsics.b(this.a, aVar.a) && this.b == aVar.b && this.c == aVar.c;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.c) + ((this.b.hashCode() + (this.a.hashCode() * 31)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("EmailConfirmationState(email=");
        sb.append(this.a);
        sb.append(", userType=");
        sb.append(this.b);
        sb.append(", hasExceededRequestLimit=");
        return android.support.v4.media.session.a.o(")", sb, this.c);
    }

    public /* synthetic */ a() {
        this("", s.a, false);
    }
}
