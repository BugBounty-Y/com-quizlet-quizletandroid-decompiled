package com.quizlet.explanations.myexplanations.ui.recyclerview;

import androidx.compose.foundation.text.z0;
import com.quizlet.explanations.myexplanations.data.p;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class f implements com.quizlet.baserecyclerview.a {
    public final p a;
    public final z0 b;

    public f(p value, z0 onClick) {
        Intrinsics.checkNotNullParameter(value, "value");
        Intrinsics.checkNotNullParameter(onClick, "onClick");
        this.a = value;
        this.b = onClick;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!f.class.equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type com.quizlet.explanations.myexplanations.ui.recyclerview.MyExplanationsQuestionAdapter.Item");
        return Intrinsics.b(this.a, ((f) obj).a);
    }

    @Override // com.quizlet.baserecyclerview.a
    public final Object getItemId() {
        return this.a.g;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "Item(value=" + this.a + ", onClick=" + this.b + ")";
    }
}
