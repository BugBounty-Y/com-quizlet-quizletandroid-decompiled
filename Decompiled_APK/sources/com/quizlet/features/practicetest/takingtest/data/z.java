package com.quizlet.features.practicetest.takingtest.data;

/* loaded from: classes3.dex */
public final class z implements E {
    public final boolean a;

    public z(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof z) && this.a == ((z) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("Back(shouldNavigateUp="), this.a);
    }
}
