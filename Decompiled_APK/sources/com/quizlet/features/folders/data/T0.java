package com.quizlet.features.folders.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class T0 {
    public final boolean a;
    public final kotlinx.collections.immutable.b b;

    public T0(kotlinx.collections.immutable.b studyModes, boolean z) {
        Intrinsics.checkNotNullParameter(studyModes, "studyModes");
        this.a = z;
        this.b = studyModes;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof T0)) {
            return false;
        }
        T0 t0 = (T0) obj;
        return this.a == t0.a && Intrinsics.b(this.b, t0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (Boolean.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "StudyButtonState(isEnabled=" + this.a + ", studyModes=" + this.b + ")";
    }
}
