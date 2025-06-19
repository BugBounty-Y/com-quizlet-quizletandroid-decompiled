package com.quizlet.remote.model.practicetests;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestConfiguration {
    public final int a;
    public final List b;
    public final Long c;
    public final String d;
    public final boolean e;
    public final boolean f;

    public PracticeTestConfiguration(int i, List questionFormats, Long l, String testView, boolean z, boolean z2) {
        Intrinsics.checkNotNullParameter(questionFormats, "questionFormats");
        Intrinsics.checkNotNullParameter(testView, "testView");
        this.a = i;
        this.b = questionFormats;
        this.c = l;
        this.d = testView;
        this.e = z;
        this.f = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestConfiguration)) {
            return false;
        }
        PracticeTestConfiguration practiceTestConfiguration = (PracticeTestConfiguration) obj;
        return this.a == practiceTestConfiguration.a && Intrinsics.b(this.b, practiceTestConfiguration.b) && Intrinsics.b(this.c, practiceTestConfiguration.c) && Intrinsics.b(this.d, practiceTestConfiguration.d) && this.e == practiceTestConfiguration.e && this.f == practiceTestConfiguration.f;
    }

    public final int hashCode() {
        int iF = d0.f(Integer.hashCode(this.a) * 31, 31, this.b);
        Long l = this.c;
        return Boolean.hashCode(this.f) + d0.g(d0.e((iF + (l == null ? 0 : l.hashCode())) * 31, 31, this.d), 31, this.e);
    }

    public final String toString() {
        return "PracticeTestConfiguration(questionCount=" + this.a + ", questionFormats=" + this.b + ", testTimer=" + this.c + ", testView=" + this.d + ", enableTestTimer=" + this.e + ", enableTimerSound=" + this.f + ")";
    }

    public /* synthetic */ PracticeTestConfiguration(int i, List list, Long l, String str, boolean z, boolean z2, int i2, DefaultConstructorMarker defaultConstructorMarker) {
        this(i, list, (i2 & 4) != 0 ? null : l, (i2 & 8) != 0 ? "all_at_once" : str, (i2 & 16) != 0 ? false : z, (i2 & 32) != 0 ? false : z2);
    }
}
