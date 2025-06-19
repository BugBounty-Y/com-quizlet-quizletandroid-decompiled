package com.quizlet.features.folders.data;

/* loaded from: classes3.dex */
public final class B0 implements C0 {
    public final int a;

    public B0(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof B0) && this.a == ((B0) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("ShowMessage(msgRes="), this.a, ")");
    }
}
