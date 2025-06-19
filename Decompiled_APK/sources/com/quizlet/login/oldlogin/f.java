package com.quizlet.login.oldlogin;

/* loaded from: classes3.dex */
public final class f extends c {
    public final boolean a;

    public f(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof f) && this.a == ((f) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("NavigateToUpsell(isConfirmationRequired="), this.a);
    }
}
