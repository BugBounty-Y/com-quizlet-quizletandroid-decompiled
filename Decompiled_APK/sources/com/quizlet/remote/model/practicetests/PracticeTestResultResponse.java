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
public final class PracticeTestResultResponse {
    public final List a;
    public final List b;

    public PracticeTestResultResponse(List practiceTestResult, List entitlementData) {
        Intrinsics.checkNotNullParameter(practiceTestResult, "practiceTestResult");
        Intrinsics.checkNotNullParameter(entitlementData, "entitlementData");
        this.a = practiceTestResult;
        this.b = entitlementData;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestResultResponse)) {
            return false;
        }
        PracticeTestResultResponse practiceTestResultResponse = (PracticeTestResultResponse) obj;
        return Intrinsics.b(this.a, practiceTestResultResponse.a) && Intrinsics.b(this.b, practiceTestResultResponse.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "PracticeTestResultResponse(practiceTestResult=" + this.a + ", entitlementData=" + this.b + ")";
    }

    public PracticeTestResultResponse(List list, List list2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list, (i & 2) != 0 ? K.a : list2);
    }
}
