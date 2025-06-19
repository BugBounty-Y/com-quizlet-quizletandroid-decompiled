package com.quizlet.data.model;

import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class K0 {
    public final int a;
    public final ArrayList b;
    public final ArrayList c;
    public final ArrayList d;
    public final com.quizlet.generated.enums.C0 e;
    public final boolean f;
    public final boolean g;
    public final Long h;

    public K0(int i, ArrayList questionFormats, ArrayList mediaTypes, ArrayList contentFormats, com.quizlet.generated.enums.C0 testView, boolean z, boolean z2, Long l) {
        Intrinsics.checkNotNullParameter(questionFormats, "questionFormats");
        Intrinsics.checkNotNullParameter(mediaTypes, "mediaTypes");
        Intrinsics.checkNotNullParameter(contentFormats, "contentFormats");
        Intrinsics.checkNotNullParameter(testView, "testView");
        this.a = i;
        this.b = questionFormats;
        this.c = mediaTypes;
        this.d = contentFormats;
        this.e = testView;
        this.f = z;
        this.g = z2;
        this.h = l;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof K0)) {
            return false;
        }
        K0 k0 = (K0) obj;
        return this.a == k0.a && this.b.equals(k0.b) && this.c.equals(k0.c) && this.d.equals(k0.d) && this.e == k0.e && this.f == k0.f && this.g == k0.g && Intrinsics.b(this.h, k0.h);
    }

    public final int hashCode() {
        int iG = androidx.compose.animation.d0.g(androidx.compose.animation.d0.g((this.e.hashCode() + androidx.compose.animation.d0.h(this.d, androidx.compose.animation.d0.h(this.c, androidx.compose.animation.d0.h(this.b, Integer.hashCode(this.a) * 31, 31), 31), 31)) * 31, 31, this.f), 31, this.g);
        Long l = this.h;
        return iG + (l == null ? 0 : l.hashCode());
    }

    public final String toString() {
        return "PracticeTestConfiguration(questionCount=" + this.a + ", questionFormats=" + this.b + ", mediaTypes=" + this.c + ", contentFormats=" + this.d + ", testView=" + this.e + ", enableTestTimer=" + this.f + ", enableTimerSound=" + this.g + ", testTimer=" + this.h + ")";
    }
}
