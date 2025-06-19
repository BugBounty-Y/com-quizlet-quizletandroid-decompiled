package com.quizlet.features.notes.data;

/* loaded from: classes3.dex */
public final class i implements x {
    public final boolean a;

    public i(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && this.a == ((i) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("Deleted(isCtaVisible="), this.a);
    }
}
