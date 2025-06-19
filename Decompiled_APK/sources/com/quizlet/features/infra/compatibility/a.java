package com.quizlet.features.infra.compatibility;

import androidx.compose.animation.d0;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a {
    public final String a;
    public final String b;
    public final Function0 c;

    public a(String userMessage, String userMessageTitle, Function0 function0) {
        Intrinsics.checkNotNullParameter(userMessage, "userMessage");
        Intrinsics.checkNotNullParameter(userMessageTitle, "userMessageTitle");
        this.a = userMessage;
        this.b = userMessageTitle;
        this.c = function0;
    }

    public static a a(a aVar, Function0 function0) {
        String userMessage = aVar.a;
        String userMessageTitle = aVar.b;
        Intrinsics.checkNotNullParameter(userMessage, "userMessage");
        Intrinsics.checkNotNullParameter(userMessageTitle, "userMessageTitle");
        return new a(userMessage, userMessageTitle, function0);
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
        Function0 function0 = this.c;
        return iE + (function0 == null ? 0 : function0.hashCode());
    }

    public final String toString() {
        return "CompatibilityCheckMessage(userMessage=" + this.a + ", userMessageTitle=" + this.b + ", action=" + this.c + ")";
    }
}
