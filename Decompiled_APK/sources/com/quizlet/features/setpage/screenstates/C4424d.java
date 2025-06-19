package com.quizlet.features.setpage.screenstates;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.setpage.screenstates.d, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4424d extends h {
    public final com.quizlet.qutils.string.f a;
    public final boolean b;

    public C4424d(com.quizlet.qutils.string.f stringResData, boolean z) {
        Intrinsics.checkNotNullParameter(stringResData, "stringResData");
        this.a = stringResData;
        this.b = z;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4424d)) {
            return false;
        }
        C4424d c4424d = (C4424d) obj;
        return this.a.equals(c4424d.a) && this.b == c4424d.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("ShowErrorDialog(stringResData=");
        sb.append(this.a);
        sb.append(", finishOnDismiss=");
        return android.support.v4.media.session.a.o(")", sb, this.b);
    }
}
