package com.quizlet.features.universaluploadflow.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class o implements r {
    public final L a;

    public o(L uploadOption) {
        Intrinsics.checkNotNullParameter(uploadOption, "uploadOption");
        this.a = uploadOption;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof o) && this.a == ((o) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "UploadButtonClicked(uploadOption=" + this.a + ")";
    }
}
