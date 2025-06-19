package com.quizlet.login.authentication.data;

/* loaded from: classes3.dex */
public final class d extends i {
    public final boolean a;

    public d(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof d) && this.a == ((d) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("CouldNotLogin(showErrorToast="), this.a);
    }
}
