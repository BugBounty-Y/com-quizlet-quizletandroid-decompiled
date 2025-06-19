package com.quizlet.features.notes.common.events;

/* loaded from: classes3.dex */
public final class r implements y {
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
        return android.support.v4.media.session.a.o(")", new StringBuilder("PrivacySettingsSaveButtonClicked(isVisible="), this.a);
    }
}
