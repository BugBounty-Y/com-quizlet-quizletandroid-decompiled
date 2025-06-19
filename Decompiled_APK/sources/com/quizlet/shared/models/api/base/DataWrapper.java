package com.quizlet.shared.models.api.base;

import android.support.v4.media.session.a;
import assistantMode.enums.p;
import com.quizlet.shared.models.api.grading.LongtextGradingResult;
import com.quizlet.shared.models.api.notes.CreateStudyNotesResponse$$serializer;
import com.quizlet.shared.models.api.notes.StudyNotesArtifactsResponse$$serializer;
import com.quizlet.shared.models.api.notes.StudyNotesResponse$$serializer;
import com.quizlet.shared.models.api.srs.SrsResponse;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.serialization.KSerializer;
import kotlinx.serialization.f;
import kotlinx.serialization.internal.C5048d;
import kotlinx.serialization.internal.q0;
import org.jetbrains.annotations.NotNull;

@f
@Metadata
/* loaded from: classes3.dex */
public final class DataWrapper {

    @NotNull
    public static final Companion Companion = new Companion();
    public static final KSerializer[] h = {null, null, new C5048d(CreateStudyNotesResponse$$serializer.INSTANCE, 0), new C5048d(StudyNotesArtifactsResponse$$serializer.INSTANCE, 0), new C5048d(StudyNotesResponse$$serializer.INSTANCE, 0), new C5048d(q0.a, 0), new C5048d(p.f, 0)};
    public final LongtextGradingResult a;
    public final SrsResponse b;
    public final List c;
    public final List d;
    public final List e;
    public final List f;
    public final List g;

    @Metadata
    public static final class Companion {
        @NotNull
        public final KSerializer serializer() {
            return DataWrapper$$serializer.INSTANCE;
        }
    }

    public /* synthetic */ DataWrapper(int i, LongtextGradingResult longtextGradingResult, SrsResponse srsResponse, List list, List list2, List list3, List list4, List list5) {
        if ((i & 1) == 0) {
            this.a = null;
        } else {
            this.a = longtextGradingResult;
        }
        if ((i & 2) == 0) {
            this.b = null;
        } else {
            this.b = srsResponse;
        }
        if ((i & 4) == 0) {
            this.c = null;
        } else {
            this.c = list;
        }
        if ((i & 8) == 0) {
            this.d = null;
        } else {
            this.d = list2;
        }
        if ((i & 16) == 0) {
            this.e = null;
        } else {
            this.e = list3;
        }
        if ((i & 32) == 0) {
            this.f = null;
        } else {
            this.f = list4;
        }
        if ((i & 64) == 0) {
            this.g = null;
        } else {
            this.g = list5;
        }
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof DataWrapper)) {
            return false;
        }
        DataWrapper dataWrapper = (DataWrapper) obj;
        return Intrinsics.b(this.a, dataWrapper.a) && Intrinsics.b(this.b, dataWrapper.b) && Intrinsics.b(this.c, dataWrapper.c) && Intrinsics.b(this.d, dataWrapper.d) && Intrinsics.b(this.e, dataWrapper.e) && Intrinsics.b(this.f, dataWrapper.f) && Intrinsics.b(this.g, dataWrapper.g);
    }

    public final int hashCode() {
        LongtextGradingResult longtextGradingResult = this.a;
        int iHashCode = (longtextGradingResult == null ? 0 : longtextGradingResult.hashCode()) * 31;
        SrsResponse srsResponse = this.b;
        int iHashCode2 = (iHashCode + (srsResponse == null ? 0 : srsResponse.hashCode())) * 31;
        List list = this.c;
        int iHashCode3 = (iHashCode2 + (list == null ? 0 : list.hashCode())) * 31;
        List list2 = this.d;
        int iHashCode4 = (iHashCode3 + (list2 == null ? 0 : list2.hashCode())) * 31;
        List list3 = this.e;
        int iHashCode5 = (iHashCode4 + (list3 == null ? 0 : list3.hashCode())) * 31;
        List list4 = this.f;
        int iHashCode6 = (iHashCode5 + (list4 == null ? 0 : list4.hashCode())) * 31;
        List list5 = this.g;
        return iHashCode6 + (list5 != null ? list5.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("DataWrapper(longtextGradingResult=");
        sb.append(this.a);
        sb.append(", srsResponse=");
        sb.append(this.b);
        sb.append(", newStudyNotes=");
        sb.append(this.c);
        sb.append(", studyNotesArtifacts=");
        sb.append(this.d);
        sb.append(", studyNotes=");
        sb.append(this.e);
        sb.append(", features=");
        sb.append(this.f);
        sb.append(", studiableMetadataStatus=");
        return a.n(")", sb, this.g);
    }
}
