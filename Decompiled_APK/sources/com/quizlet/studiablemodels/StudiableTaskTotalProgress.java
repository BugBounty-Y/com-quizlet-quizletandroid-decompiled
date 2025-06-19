package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableTaskTotalProgress implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableTaskTotalProgress> CREATOR = new f(15);
    public final double a;

    public StudiableTaskTotalProgress(double d) {
        this.a = d;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof StudiableTaskTotalProgress) && Double.compare(this.a, ((StudiableTaskTotalProgress) obj).a) == 0;
    }

    public final int hashCode() {
        return Double.hashCode(this.a);
    }

    public final String toString() {
        return "StudiableTaskTotalProgress(totalProgress=" + this.a + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeDouble(this.a);
    }
}
