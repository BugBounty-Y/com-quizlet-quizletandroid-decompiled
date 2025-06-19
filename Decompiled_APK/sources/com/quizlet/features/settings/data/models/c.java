package com.quizlet.features.settings.data.models;

/* loaded from: classes3.dex */
public final class c implements e {
    public final boolean a;

    public c(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && this.a == ((c) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("Available(isOfflineStudyingEnabled="), this.a);
    }
}
