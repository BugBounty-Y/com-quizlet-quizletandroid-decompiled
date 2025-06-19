package com.quizlet.features.practicetest.detail.data;

import androidx.compose.animation.d0;
import com.quizlet.features.practicetest.common.data.PracticeTestConfigurationData;
import java.util.List;
import java.util.Map;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class F implements I {
    public final String a;
    public final String b;
    public final String c;
    public final int d;
    public final boolean e;
    public final String f;
    public final List g;
    public final List h;
    public final Map i;
    public final PracticeTestConfigurationData j;
    public final boolean k;
    public final boolean l;
    public final boolean m;
    public final Boolean n;
    public final int o;

    public F(String title, String str, String str2, int i, boolean z, String createdDate, List pastExams, List questions, Map questionCounts, PracticeTestConfigurationData practiceTestConfigurationData, boolean z2, boolean z3, boolean z4, Boolean bool, int i2) {
        Intrinsics.checkNotNullParameter(title, "title");
        Intrinsics.checkNotNullParameter(createdDate, "createdDate");
        Intrinsics.checkNotNullParameter(pastExams, "pastExams");
        Intrinsics.checkNotNullParameter(questions, "questions");
        Intrinsics.checkNotNullParameter(questionCounts, "questionCounts");
        Intrinsics.checkNotNullParameter(practiceTestConfigurationData, "practiceTestConfigurationData");
        this.a = title;
        this.b = str;
        this.c = str2;
        this.d = i;
        this.e = z;
        this.f = createdDate;
        this.g = pastExams;
        this.h = questions;
        this.i = questionCounts;
        this.j = practiceTestConfigurationData;
        this.k = z2;
        this.l = z3;
        this.m = z4;
        this.n = bool;
        this.o = i2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof F)) {
            return false;
        }
        F f = (F) obj;
        return Intrinsics.b(this.a, f.a) && Intrinsics.b(this.b, f.b) && Intrinsics.b(this.c, f.c) && this.d == f.d && this.e == f.e && Intrinsics.b(this.f, f.f) && Intrinsics.b(this.g, f.g) && Intrinsics.b(this.h, f.h) && Intrinsics.b(this.i, f.i) && Intrinsics.b(this.j, f.j) && this.k == f.k && this.l == f.l && this.m == f.m && Intrinsics.b(this.n, f.n) && this.o == f.o;
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        String str = this.b;
        int iHashCode2 = (iHashCode + (str == null ? 0 : str.hashCode())) * 31;
        String str2 = this.c;
        int iG = d0.g(d0.g(d0.g((this.j.hashCode() + assistantMode.refactored.a.d(d0.f(d0.f(d0.e(d0.g(d0.b(this.d, (iHashCode2 + (str2 == null ? 0 : str2.hashCode())) * 31, 31), 31, this.e), 31, this.f), 31, this.g), 31, this.h), 31, this.i)) * 31, 31, this.k), 31, this.l), 31, this.m);
        Boolean bool = this.n;
        return Integer.hashCode(this.o) + ((iG + (bool != null ? bool.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("Content(title=");
        sb.append(this.a);
        sb.append(", username=");
        sb.append(this.b);
        sb.append(", userImage=");
        sb.append(this.c);
        sb.append(", userBadge=");
        sb.append(this.d);
        sb.append(", isVerified=");
        sb.append(this.e);
        sb.append(", createdDate=");
        sb.append(this.f);
        sb.append(", pastExams=");
        sb.append(this.g);
        sb.append(", questions=");
        sb.append(this.h);
        sb.append(", questionCounts=");
        sb.append(this.i);
        sb.append(", practiceTestConfigurationData=");
        sb.append(this.j);
        sb.append(", isLoggedIn=");
        sb.append(this.k);
        sb.append(", shouldShowSettings=");
        sb.append(this.l);
        sb.append(", isPrivate=");
        sb.append(this.m);
        sb.append(", canUsePracticeTestsFeature=");
        sb.append(this.n);
        sb.append(", freeTrialDays=");
        return android.support.v4.media.session.a.r(sb, this.o, ")");
    }
}
