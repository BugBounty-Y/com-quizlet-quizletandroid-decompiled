package com.quizlet.explanations.myexplanations.ui.recyclerview;

import androidx.compose.foundation.text.z0;
import com.quizlet.explanations.myexplanations.data.q;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class h implements com.quizlet.baserecyclerview.a {
    public final q a;
    public final z0 b;

    public h(q value, z0 onClick) {
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        this.a = value;
        this.b = onClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!h.class.equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type com.quizlet.explanations.myexplanations.ui.recyclerview.MyExplanationsTextbookAdapter.Item");
        return Intrinsics.b(this.a, ((h) obj).a);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return this.a.j;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Item(value=" + this.a + ", onClick=" + this.b + ")";
    }
}
