package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableRoundProgress implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableRoundProgress> CREATOR = new f(13);
    public final int a;
    public final int b;

    public StudiableRoundProgress(int i, int i2) {
        this.a = i;
        this.b = i2;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableRoundProgress)) {
            return false;
        }
        StudiableRoundProgress studiableRoundProgress = (StudiableRoundProgress) obj;
        return this.a == studiableRoundProgress.a && this.b == studiableRoundProgress.b;
    }

    public final int hashCode() {
        return Integer.hashCode(this.b) + (Integer.hashCode(this.a) * 31);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudiableRoundProgress(numerator=");
        sb.append(this.a);
        sb.append(", denominator=");
        return android.support.v4.media.session.a.r(sb, this.b, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeInt(this.a);
        dest.writeInt(this.b);
    }
}
