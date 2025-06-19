package com.quizlet.features.infra.basestudy.data.models.logging;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.onetrust.otpublishers.headless.UI.DataModels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudyEventLogData implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudyEventLogData> CREATOR = new f(2);
    public final String a;
    public final long b;
    public final long c;
    public final boolean d;

    public StudyEventLogData(long j, long j2, String studySessionId, boolean z) {
        Intrinsics.checkNotNullParameter(studySessionId, "studySessionId");
        this.a = studySessionId;
        this.b = j;
        this.c = j2;
        this.d = z;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudyEventLogData)) {
            return false;
        }
        StudyEventLogData studyEventLogData = (StudyEventLogData) obj;
        return Intrinsics.b(this.a, studyEventLogData.a) && this.b == studyEventLogData.b && this.c == studyEventLogData.c && this.d == studyEventLogData.d;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.d) + d0.d(d0.d(this.a.hashCode() * 31, 31, this.b), 31, this.c);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudyEventLogData(studySessionId=");
        sb.append(this.a);
        sb.append(", studyableId=");
        sb.append(this.b);
        sb.append(", studyableLocalId=");
        sb.append(this.c);
        sb.append(", selectedTermsOnly=");
        return android.support.v4.media.session.a.o(")", sb, this.d);
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a);
        dest.writeLong(this.b);
        dest.writeLong(this.c);
        dest.writeInt(this.d ? 1 : 0);
    }
}
