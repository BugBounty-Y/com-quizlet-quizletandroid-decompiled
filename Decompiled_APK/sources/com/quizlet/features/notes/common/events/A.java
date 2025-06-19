package com.quizlet.features.notes.common.events;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class A implements y {
    public final String a;

    public A(String text) {
        Intrinsics.checkNotNullParameter(text, "text");
        this.a = text;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof A) && Intrinsics.b(this.a, ((A) obj).a);
    }

    public final int hashCode() {
        return this.a.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.t(new StringBuilder("StartTransformingButtonClick(text="), this.a, ")");
    }
}
