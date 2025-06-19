package com.quizlet.data.model;

import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class R0 {
    public final String a;
    public final String b;

    public R0(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof R0)) {
            return false;
        }
        R0 r0 = (R0) obj;
        return Intrinsics.b(this.a, r0.a) && Intrinsics.b(this.b, r0.b);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestImageData(imageUrl=");
        sb.append(this.a);
        sb.append(", imageCaption=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
