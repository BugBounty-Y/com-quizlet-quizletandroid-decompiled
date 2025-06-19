package com.quizlet.search.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements com.quizlet.ui.models.search.a {
    public final a a;
    public final boolean b;

    public b(a type) {
        Intrinsics.checkNotNullParameter(type, "type");
        this.a = type;
        this.b = type != a.f;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof b) && this.a == ((b) obj).a;
    }

    @Override // com.quizlet.ui.models.search.a
    public final Object getKey() {
        return this.a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "HeaderUiModel(type=" + this.a + ")";
    }
}
