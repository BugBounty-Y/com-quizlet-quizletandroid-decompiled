package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import com.quizlet.studiablemodels.f;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class PSmartGradedAnswerMetadata extends PGradedAnswerMetadata {

    @NotNull
    public static final Parcelable.Creator<PSmartGradedAnswerMetadata> CREATOR = new f(26);
    public final PLongtextGradingResult b;
    public final boolean c;
    public final long d;
    public final long e;
    public final Long f;

    public PSmartGradedAnswerMetadata(PLongtextGradingResult pLongtextGradingResult, boolean z, long j, long j2, Long l) {
        super(true);
        this.b = pLongtextGradingResult;
        this.c = z;
        this.d = j;
        this.e = j2;
        this.f = l;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof PSmartGradedAnswerMetadata)) {
            return false;
        }
        PSmartGradedAnswerMetadata pSmartGradedAnswerMetadata = (PSmartGradedAnswerMetadata) obj;
        return Intrinsics.b(this.b, pSmartGradedAnswerMetadata.b) && this.c == pSmartGradedAnswerMetadata.c && this.d == pSmartGradedAnswerMetadata.d && this.e == pSmartGradedAnswerMetadata.e && Intrinsics.b(this.f, pSmartGradedAnswerMetadata.f);
    }

    public final int hashCode() {
        PLongtextGradingResult pLongtextGradingResult = this.b;
        int iD = d0.d(d0.d(d0.g((pLongtextGradingResult == null ? 0 : pLongtextGradingResult.hashCode()) * 31, 31, this.c), 31, this.d), 31, this.e);
        Long l = this.f;
        return iD + (l != null ? l.hashCode() : 0);
    }

    public final String toString() {
        return "PSmartGradedAnswerMetadata(longtextGradingResult=" + this.b + ", wasRequestSuccess=" + this.c + ", logStartTimestamp=" + this.d + ", logEndTimestamp=" + this.e + ", logGradedResultTimestamp=" + this.f + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        PLongtextGradingResult pLongtextGradingResult = this.b;
        if (pLongtextGradingResult == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            pLongtextGradingResult.writeToParcel(dest, i);
        }
        dest.writeInt(this.c ? 1 : 0);
        dest.writeLong(this.d);
        dest.writeLong(this.e);
        Long l = this.f;
        if (l == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeLong(l.longValue());
        }
    }
}
