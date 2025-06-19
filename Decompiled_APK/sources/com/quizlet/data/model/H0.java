package com.quizlet.data.model;

import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class H0 {
    public final String a;
    public final List b;

    public H0(String section, List studyNotes) {
        Intrinsics.checkNotNullParameter(section, "section");
        Intrinsics.checkNotNullParameter(studyNotes, "studyNotes");
        this.a = section;
        this.b = studyNotes;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof H0)) {
            return false;
        }
        H0 h0 = (H0) obj;
        return Intrinsics.b(this.a, h0.a) && Intrinsics.b(this.b, h0.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "NotesToValueWithSection(section=" + this.a + ", studyNotes=" + this.b + ")";
    }
}
