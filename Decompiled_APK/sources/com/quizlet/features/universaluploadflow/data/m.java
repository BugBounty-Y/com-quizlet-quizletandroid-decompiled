package com.quizlet.features.universaluploadflow.data;

/* loaded from: classes3.dex */
public final class m implements r {
    public final boolean a;

    public m(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof m) && this.a == ((m) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("SavePrivacySettingsClicked(isPublic="), this.a);
    }
}
