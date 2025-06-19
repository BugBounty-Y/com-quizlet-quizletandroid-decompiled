package com.quizlet.features.practicetest.detail.data;

/* renamed from: com.quizlet.features.practicetest.detail.data.i, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4406i implements p {
    public final boolean a;

    public C4406i(boolean z) {
        this.a = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof C4406i) && this.a == ((C4406i) obj).a;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.a);
    }

    public final String toString() {
        return android.support.v4.media.session.a.o(")", new StringBuilder("SavePrivacySettingsClicked(isPublic="), this.a);
    }
}
