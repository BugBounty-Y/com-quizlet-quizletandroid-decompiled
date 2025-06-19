package com.quizlet.login.common.interactors.data;

/* loaded from: classes3.dex */
public final class n extends z {
    public final boolean a;

    public n(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof n) && this.a == ((n) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("CouldNotLogin(shouldShowError="), this.a);
    }
}
