package com.quizlet.remote.model.universaluploadflow;

import androidx.compose.animation.d0;
import com.squareup.moshi.m;
import java.util.List;
import kotlin.Metadata;
import kotlin.collections.K;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;

@m(generateAdapter = true)
@Metadata
/* loaded from: classes3.dex */
public final class UniversalUploadFlowFlashcardSetsResponse {
    public final List a;
    public final List b;
    public final List c;
    public final List d;

    public UniversalUploadFlowFlashcardSetsResponse(List classSet, List set, List session, List list) {
        Intrinsics.checkNotNullParameter(classSet, "classSet");
        Intrinsics.checkNotNullParameter(set, "set");
        Intrinsics.checkNotNullParameter(session, "session");
        this.a = classSet;
        this.b = set;
        this.c = session;
        this.d = list;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof UniversalUploadFlowFlashcardSetsResponse)) {
            return false;
        }
        UniversalUploadFlowFlashcardSetsResponse universalUploadFlowFlashcardSetsResponse = (UniversalUploadFlowFlashcardSetsResponse) obj;
        return Intrinsics.b(this.a, universalUploadFlowFlashcardSetsResponse.a) && Intrinsics.b(this.b, universalUploadFlowFlashcardSetsResponse.b) && Intrinsics.b(this.c, universalUploadFlowFlashcardSetsResponse.c) && Intrinsics.b(this.d, universalUploadFlowFlashcardSetsResponse.d);
    }

    public final int hashCode() {
        int iF = d0.f(d0.f(this.a.hashCode() * 31, 31, this.b), 31, this.c);
        List list = this.d;
        return iF + (list == null ? 0 : list.hashCode());
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("UniversalUploadFlowFlashcardSetsResponse(classSet=");
        sb.append(this.a);
        sb.append(", set=");
        sb.append(this.b);
        sb.append(", session=");
        sb.append(this.c);
        sb.append(", user=");
        return android.support.v4.media.session.a.n(")", sb, this.d);
    }

    public UniversalUploadFlowFlashcardSetsResponse(List list, List list2, List list3, List list4, int i, DefaultConstructorMarker defaultConstructorMarker) {
        this((i & 1) != 0 ? K.a : list, (i & 2) != 0 ? K.a : list2, (i & 4) != 0 ? K.a : list3, (i & 8) != 0 ? K.a : list4);
    }
}
