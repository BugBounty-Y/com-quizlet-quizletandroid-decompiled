package com.quizlet.remote.model.practicetests;

import com.squareup.moshi.m;
import kotlin.Metadata;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class PracticeTestsImageDataResponse {
    public final String a;
    public final String b;

    public PracticeTestsImageDataResponse(String str, String str2) {
        this.a = str;
        this.b = str2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PracticeTestsImageDataResponse)) {
            return false;
        }
        PracticeTestsImageDataResponse practiceTestsImageDataResponse = (PracticeTestsImageDataResponse) obj;
        return Intrinsics.b(this.a, practiceTestsImageDataResponse.a) && Intrinsics.b(this.b, practiceTestsImageDataResponse.b);
    }

    public final int hashCode() {
        String str = this.a;
        int iHashCode = (str == null ? 0 : str.hashCode()) * 31;
        String str2 = this.b;
        return iHashCode + (str2 != null ? str2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("PracticeTestsImageDataResponse(signedUrl=");
        sb.append(this.a);
        sb.append(", imageCaption=");
        return android.support.v4.media.session.a.t(sb, this.b, ")");
    }

    public /* synthetic */ PracticeTestsImageDataResponse(String str, String str2, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? null : str, (i & 2) != 0 ? null : str2);
    }
}
