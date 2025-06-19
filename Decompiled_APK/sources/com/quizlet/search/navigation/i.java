package com.quizlet.search.navigation;

import com.quizlet.search.data.term.TermSearchUiModel;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends l {
    public final TermSearchUiModel a;

    public i(TermSearchUiModel model) {
        Intrinsics.checkNotNullParameter(model, "model");
        this.a = model;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof i) && Intrinsics.b(this.a, ((i) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "TermConvertibleModal(model=" + this.a + ")";
    }
}
