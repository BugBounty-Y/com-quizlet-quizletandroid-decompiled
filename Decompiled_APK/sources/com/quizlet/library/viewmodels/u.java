package com.quizlet.library.viewmodels;

import androidx.camera.camera2.internal.AbstractC0147y;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class u implements e {
    public final String a;
    public final String b;

    public u(String section) {
        Intrinsics.checkNotNullParameter(section, "section");
        this.a = section;
        this.b = AbstractC0147y.d("section_", section);
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof u) && Intrinsics.b(this.a, ((u) obj).a);
    }

    @Override // com.quizlet.library.viewmodels.e
    public final String getKey() {
        return this.b;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("PracticeTestSection(section="), this.a, ")");
    }
}
