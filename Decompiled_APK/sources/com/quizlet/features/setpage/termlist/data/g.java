package com.quizlet.features.setpage.termlist.data;

import com.google.android.gms.internal.mlkit_vision_common.C;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class g extends C {
    public final m a;

    public g(m selectedOption) {
        Intrinsics.checkNotNullParameter(selectedOption, "selectedOption");
        this.a = selectedOption;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof g) && this.a == ((g) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "SelectTermListSortOrder(selectedOption=" + this.a + ")";
    }
}
