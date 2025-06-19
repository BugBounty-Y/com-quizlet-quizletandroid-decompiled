package com.quizlet.quizletandroid.ui.learnpaywall;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c {
    public final b a;

    public c(b source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && this.a == ((c) obj).a;
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return "PaywallViewData(source=" + this.a + ")";
    }
}
