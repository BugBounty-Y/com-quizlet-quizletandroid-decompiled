package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.internal.mlkit_vision_document_scanner.H6;
import com.quizlet.generated.enums.P;
import kotlin.Metadata;
import kotlin.NoWhenBranchMatchedException;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes3.dex */
public final class StudiableMeteringData implements Parcelable {

    @NotNull
    public static final Parcelable.Creator<StudiableMeteringData> CREATOR = new f(10);
    public final com.quizlet.shared.enums.h a;
    public final Integer b;
    public final Integer c;
    public final int d;
    public final Integer e;
    public final boolean f;

    public StudiableMeteringData(com.quizlet.shared.enums.h meteredEventType, Integer num, Integer num2) {
        int iMax;
        P p;
        Intrinsics.checkNotNullParameter(meteredEventType, "meteredEventType");
        this.a = meteredEventType;
        this.b = num;
        this.c = num2;
        boolean z = false;
        if (num != null) {
            int iIntValue = num.intValue();
            Intrinsics.checkNotNullParameter(meteredEventType, "<this>");
            int iOrdinal = meteredEventType.ordinal();
            if (iOrdinal == 0) {
                p = P.EXPLANATION_VIEW;
            } else if (iOrdinal == 1) {
                p = P.LEARN_CHECKPOINT;
            } else {
                if (iOrdinal != 2) {
                    throw new NoWhenBranchMatchedException();
                }
                p = P.TEST_SUBMISSION;
            }
            iMax = Math.max(iIntValue - H6.b(p), 0);
        } else {
            iMax = 0;
        }
        this.d = iMax;
        Integer numValueOf = num2 != null ? Integer.valueOf(num2.intValue() - iMax) : null;
        this.e = numValueOf;
        if (numValueOf != null) {
            z = numValueOf.intValue() <= 0;
        }
        this.f = z;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof StudiableMeteringData)) {
            return false;
        }
        StudiableMeteringData studiableMeteringData = (StudiableMeteringData) obj;
        return this.a == studiableMeteringData.a && Intrinsics.b(this.b, studiableMeteringData.b) && Intrinsics.b(this.c, studiableMeteringData.c);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        Integer num = this.b;
        int iHashCode2 = (iHashCode + (num == null ? 0 : num.hashCode())) * 31;
        Integer num2 = this.c;
        return iHashCode2 + (num2 != null ? num2.hashCode() : 0);
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("StudiableMeteringData(meteredEventType=");
        sb.append(this.a);
        sb.append(", numEvents=");
        sb.append(this.b);
        sb.append(", threshold=");
        return assistantMode.refactored.a.l(sb, this.c, ")");
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel dest, int i) {
        Intrinsics.checkNotNullParameter(dest, "dest");
        dest.writeString(this.a.name());
        Integer num = this.b;
        if (num == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeInt(num.intValue());
        }
        Integer num2 = this.c;
        if (num2 == null) {
            dest.writeInt(0);
        } else {
            dest.writeInt(1);
            dest.writeInt(num2.intValue());
        }
    }
}
