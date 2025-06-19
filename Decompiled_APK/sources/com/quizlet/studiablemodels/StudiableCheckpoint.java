package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.compose.animation.d0;
import java.util.ArrayList;
import java.util.Iterator;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableCheckpoint extends StudiableStep {

    @NotNull
    public static final Parcelable.Creator<StudiableCheckpoint> CREATOR = new f(3);
    public final AssistantCheckpointProgressState b;
    public final boolean c;
    public final ArrayList d;
    public final StudiableMeteringData e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public StudiableCheckpoint(AssistantCheckpointProgressState progressState, boolean z, ArrayList arrayList, StudiableMeteringData studiableMeteringData) {
        super(studiableMeteringData);
        Intrinsics.checkNotNullParameter(progressState, "progressState");
        this.b = progressState;
        this.c = z;
        this.d = arrayList;
        this.e = studiableMeteringData;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableCheckpoint)) {
            return false;
        }
        StudiableCheckpoint studiableCheckpoint = (StudiableCheckpoint) obj;
        return this.b == studiableCheckpoint.b && this.c == studiableCheckpoint.c && Intrinsics.b(this.d, studiableCheckpoint.d) && Intrinsics.b(this.e, studiableCheckpoint.e);
    }

    public final int hashCode() {
        int iG = d0.g(this.b.hashCode() * 31, 31, this.c);
        ArrayList arrayList = this.d;
        int iHashCode = (iG + (arrayList == null ? 0 : arrayList.hashCode())) * 31;
        StudiableMeteringData studiableMeteringData = this.e;
        return iHashCode + (studiableMeteringData != null ? studiableMeteringData.hashCode() : 0);
    }

    public final String toString() {
        return "StudiableCheckpoint(progressState=" + this.b + ", hasCompletedStudying=" + this.c + ", roundResults=" + this.d + ", meteringData=" + this.e + ")";
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        this.b.writeToParcel(dest, i);
        dest.writeInt(this.c ? 1 : 0);
        ArrayList arrayList = this.d;
        if (arrayList == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeInt(arrayList.size());
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                ((RoundResultItem) it2.next()).writeToParcel(dest, i);
            }
        }
        StudiableMeteringData studiableMeteringData = this.e;
        if (studiableMeteringData == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            studiableMeteringData.writeToParcel(dest, i);
        }
    }
}
