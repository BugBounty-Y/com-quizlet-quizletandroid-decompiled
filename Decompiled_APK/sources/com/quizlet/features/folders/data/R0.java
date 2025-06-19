package com.quizlet.features.folders.data;

import java.time.LocalDate;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class R0 {
    public final LocalDate a;
    public final boolean b;

    public R0(LocalDate localDate, boolean z) {
        this.a = localDate;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof R0)) {
            return false;
        }
        R0 r0 = (R0) obj;
        return Intrinsics.b(this.a, r0.a) && this.b == r0.b;
    }

    public final int hashCode() {
        LocalDate localDate = this.a;
        return Boolean.hashCode(this.b) + ((localDate == null ? 0 : localDate.hashCode()) * 31);
    }

    public final String toString() {
        return "ModifiedUiData(lastModifiedDate=" + this.a + ", wasModified=" + this.b + ")";
    }
}
