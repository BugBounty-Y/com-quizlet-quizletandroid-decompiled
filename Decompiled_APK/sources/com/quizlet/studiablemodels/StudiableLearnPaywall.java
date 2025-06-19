package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableLearnPaywall extends StudiableStep {

    @NotNull
    public static final Parcelable.Creator<StudiableLearnPaywall> CREATOR = new f(7);
    public final StudiableMeteringData b;

    public StudiableLearnPaywall(StudiableMeteringData studiableMeteringData) {
        super(studiableMeteringData);
        this.b = studiableMeteringData;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        return (obj instanceof StudiableLearnPaywall) && Intrinsics.b(this.b, ((StudiableLearnPaywall) obj).b);
    }

    public final int hashCode() {
        StudiableMeteringData studiableMeteringData = this.b;
        if (studiableMeteringData == null) {
            return 0;
        }
        return studiableMeteringData.hashCode();
    }

    public final String toString() {
        return "StudiableLearnPaywall(meteringData=" + this.b + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        StudiableMeteringData studiableMeteringData = this.b;
        if (studiableMeteringData == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            studiableMeteringData.writeToParcel(dest, i);
        }
    }
}
