package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestResponse {
    public final List a;
    public final List b;
    public final List c;

    public PracticeTestResponse(List list, List list2, List entitlementData) {
        Intrinsics.checkNotNullParameter(entitlementData, "entitlementData");
        this.a = list;
        this.b = list2;
        this.c = entitlementData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestResponse)) {
            return false;
        }
        PracticeTestResponse practiceTestResponse = (PracticeTestResponse) obj;
        return Intrinsics.b(this.a, practiceTestResponse.a) && Intrinsics.b(this.b, practiceTestResponse.b) && Intrinsics.b(this.c, practiceTestResponse.c);
    }

    public final int hashCode() {
        List list = this.a;
        int iHashCode = (list == null ? 0 : list.hashCode()) * 31;
        List list2 = this.b;
        return this.c.hashCode() + ((iHashCode + (list2 != null ? list2.hashCode() : 0)) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestResponse(practiceTest=");
        sb.append(this.a);
        sb.append(", redirect=");
        sb.append(this.b);
        sb.append(", entitlementData=");
        return android.support.v4.media.session.a.n(")", sb, this.c);
    }

    public PracticeTestResponse(List list, List list2, List list3, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : list, (i & 2) != 0 ? null : list2, (i & 4) != 0 ? K.a : list3);
    }
}
