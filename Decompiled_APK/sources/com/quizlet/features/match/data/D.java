package com.quizlet.features.match.data;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class D extends G {
    public final com.quizlet.qutils.string.f a;
    public final boolean b;

    public D(com.quizlet.qutils.string.f errorRes, boolean z) {
        Intrinsics.checkNotNullParameter(errorRes, "errorRes");
        this.a = errorRes;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof D)) {
            return false;
        }
        D d = (D) obj;
        return this.a.equals(d.a) && this.b == d.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Error(errorRes=");
        sb.append(this.a);
        sb.append(", useHtml=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
