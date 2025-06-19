package com.quizlet.features.practicetest.takingtest.data;

import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.quizlet.features.practicetest.takingtest.data.e, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C4411e {
    public final String a;
    public final String b;

    public C4411e(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof C4411e)) {
            return false;
        }
        C4411e c4411e = (C4411e) obj;
        return Intrinsics.b(this.a, c4411e.a) && Intrinsics.b(this.b, c4411e.b);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestImage(imageUrl=");
        sb.append(this.a);
        sb.append(", imageCaption=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }
}
