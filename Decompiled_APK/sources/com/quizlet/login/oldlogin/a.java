package com.quizlet.login.oldlogin;

import com.quizlet.login.recovery.data.ScreenState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a extends c {
    public final ScreenState a;

    public a(ScreenState accountState) {
        Intrinsics.checkNotNullParameter(accountState, "accountState");
        this.a = accountState;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && Intrinsics.b(this.a, ((a) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "LaunchAccountAlreadyExistsDialog(accountState=" + this.a + ")";
    }
}
