package com.quizlet.features.notes.common.events;

/* loaded from: classes3.dex */
public final class G implements y {
    public final boolean a;

    public G(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof G) && this.a == ((G) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("PrivacySettingsVisibilityChanged(isVisible="), this.a);
    }
}
