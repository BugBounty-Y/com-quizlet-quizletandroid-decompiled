package com.quizlet.features.setpage.state;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends d {
    public final Object a;

    public c(Object obj) {
        this.a = obj;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof c) && Intrinsics.b(this.a, ((c) obj).a);
    }

    public final int hashCode() {
        Object obj = this.a;
        if (obj == null) {
            return 0;
        }
        return obj.hashCode();
    }

    public final String toString() {
        return android.support.v4.media.session.a.s(new StringBuilder("Success(data="), this.a, ")");
    }
}
