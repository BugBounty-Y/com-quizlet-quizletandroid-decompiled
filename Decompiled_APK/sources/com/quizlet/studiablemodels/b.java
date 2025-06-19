package com.quizlet.studiablemodels;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.studiablemodels.FillInTheBlankStudiableSegment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        parcel.readInt();
        return FillInTheBlankStudiableSegment.Blank.a;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new FillInTheBlankStudiableSegment.Blank[i];
    }
}
