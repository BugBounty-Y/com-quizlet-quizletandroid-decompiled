package com.quizlet.features.folders.data;

/* loaded from: classes3.dex */
public final class N implements T {
    public final boolean a;

    public N(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof N) && this.a == ((N) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("TagUpdated(success="), this.a);
    }
}
