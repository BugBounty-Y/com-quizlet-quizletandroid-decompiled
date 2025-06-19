package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class RoundResultItem implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<RoundResultItem> CREATOR = new f(1);
    public final long a;
    public final boolean b;

    public RoundResultItem(long j, boolean z) {
        this.a = j;
        this.b = z;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof RoundResultItem)) {
            return false;
        }
        RoundResultItem roundResultItem = (RoundResultItem) obj;
        return this.a == roundResultItem.a && this.b == roundResultItem.b;
    }

    public final int hashCode() {
        return Boolean.hashCode(this.b) + (Long.hashCode(this.a) * 31);
    }

    public final String toString() {
        return "RoundResultItem(studiableItemId=" + this.a + ", isCorrect=" + this.b + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeLong(this.a);
        dest.writeInt(this.b ? 1 : 0);
    }
}
