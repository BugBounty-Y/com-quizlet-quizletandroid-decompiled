package com.quizlet.quizletandroid.ui.startpage.nav2.usecases;

import com.quizlet.generated.enums.H;
import com.quizlet.generated.enums.S0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntRange;

/* loaded from: classes3.dex */
public final class a {
    public final S0 a;
    public final H b;
    public final IntRange c;
    public final Integer d;

    public a(S0 revisionCenterType, H countryCode, IntRange intRange, Integer num, int i) {
        intRange = (i & 4) != 0 ? null : intRange;
        num = (i & 8) != 0 ? null : num;
        Intrinsics.checkNotNullParameter(revisionCenterType, "revisionCenterType");
        Intrinsics.checkNotNullParameter(countryCode, "countryCode");
        this.a = revisionCenterType;
        this.b = countryCode;
        this.c = intRange;
        this.d = num;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof a)) {
            return false;
        }
        a aVar = (a) obj;
        return this.a == aVar.a && this.b == aVar.b && Intrinsics.b(this.c, aVar.c) && Intrinsics.b(this.d, aVar.d);
    }

    public final int hashCode() {
        int iHashCode = (this.b.hashCode() + (this.a.hashCode() * 31)) * 31;
        IntRange intRange = this.c;
        int iHashCode2 = (iHashCode + (intRange == null ? 0 : intRange.hashCode())) * 31;
        Integer num = this.d;
        return iHashCode2 + (num != null ? num.hashCode() : 0);
    }

    public final String toString() {
        return "RevisionCenterEligibilityData(revisionCenterType=" + this.a + ", countryCode=" + this.b + ", ageRange=" + this.c + ", daysLeft=" + this.d + ")";
    }
}
