package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import java.util.Iterator;
import java.util.List;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableWriteMasteryBuckets implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableWriteMasteryBuckets> CREATOR = new f(18);
    public final List a;
    public final List b;

    public StudiableWriteMasteryBuckets(List correctZeroTimes, List correctOneTime) {
        Intrinsics.checkNotNullParameter(correctZeroTimes, "correctZeroTimes");
        Intrinsics.checkNotNullParameter(correctOneTime, "correctOneTime");
        this.a = correctZeroTimes;
        this.b = correctOneTime;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableWriteMasteryBuckets)) {
            return false;
        }
        StudiableWriteMasteryBuckets studiableWriteMasteryBuckets = (StudiableWriteMasteryBuckets) obj;
        return Intrinsics.b(this.a, studiableWriteMasteryBuckets.a) && Intrinsics.b(this.b, studiableWriteMasteryBuckets.b);
    }

    public final int hashCode() {
        return this.b.hashCode() + (this.a.hashCode() * 31);
    }

    public final String toString() {
        return "StudiableWriteMasteryBuckets(correctZeroTimes=" + this.a + ", correctOneTime=" + this.b + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        List list = this.a;
        dest.writeInt(list.size());
        Iterator it2 = list.iterator();
        while (it2.hasNext()) {
            dest.writeLong(((Number) it2.next()).longValue());
        }
        List list2 = this.b;
        dest.writeInt(list2.size());
        Iterator it3 = list2.iterator();
        while (it3.hasNext()) {
            dest.writeLong(((Number) it3.next()).longValue());
        }
    }
}
