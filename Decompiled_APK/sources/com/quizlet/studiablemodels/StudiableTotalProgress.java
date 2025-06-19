package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableTotalProgress implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableTotalProgress> CREATOR = new f(17);
    public final StudiableWriteMasteryBuckets a;
    public final double b;

    public StudiableTotalProgress(StudiableWriteMasteryBuckets masteryBuckets, double d) {
        Intrinsics.checkNotNullParameter(masteryBuckets, "masteryBuckets");
        this.a = masteryBuckets;
        this.b = d;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableTotalProgress)) {
            return false;
        }
        StudiableTotalProgress studiableTotalProgress = (StudiableTotalProgress) obj;
        return Intrinsics.b(this.a, studiableTotalProgress.a) && Double.compare(this.b, studiableTotalProgress.b) == 0;
    }

    public final int hashCode() {
        return Double.hashCode(this.b) + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "StudiableTotalProgress(masteryBuckets=" + this.a + ", studyProgress=" + this.b + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        this.a.writeToParcel(dest, i);
        dest.writeDouble(this.b);
    }
}
