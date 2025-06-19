package com.quizlet.features.folders.addtofolder.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements n {
    public final o a;

    public a(o filterType) {
        Intrinsics.checkNotNullParameter(filterType, "filterType");
        this.a = filterType;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof a) && this.a == ((a) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "ChangeOption(filterType=" + this.a + ")";
    }
}
