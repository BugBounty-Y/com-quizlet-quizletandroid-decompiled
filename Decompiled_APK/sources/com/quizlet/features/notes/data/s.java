package com.quizlet.features.notes.data;

/* loaded from: classes3.dex */
public final class s implements x {
    public final boolean a;

    public s(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof s) && this.a == ((s) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("Private(isCtaVisible="), this.a);
    }
}
