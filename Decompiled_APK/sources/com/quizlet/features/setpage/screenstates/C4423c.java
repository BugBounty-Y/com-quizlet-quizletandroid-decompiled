package com.quizlet.features.setpage.screenstates;

/* renamed from: com.quizlet.features.setpage.screenstates.c, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4423c extends h {
    public final int a;

    public C4423c(int i) {
        this.a = i;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4423c) && this.a == ((C4423c) obj).a;
    }

    public final int hashCode() {
        return Integer.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.r(new StringBuilder("ShowCopyFailedError(errorRes="), this.a, ")");
    }
}
