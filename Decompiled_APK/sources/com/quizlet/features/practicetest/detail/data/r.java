package com.quizlet.features.practicetest.detail.data;

/* loaded from: classes3.dex */
public final class r implements D {
    public final boolean a;

    public r(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof r) && this.a == ((r) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("ErrorModal(isInternetConnectionError="), this.a);
    }
}
