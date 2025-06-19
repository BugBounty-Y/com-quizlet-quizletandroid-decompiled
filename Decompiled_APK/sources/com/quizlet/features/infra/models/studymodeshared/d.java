package com.quizlet.features.infra.models.studymodeshared;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        long j = parcel.readLong();
        int i = parcel.readInt();
        LinkedHashSet linkedHashSet = new LinkedHashSet(i);
        for (int i2 = 0; i2 != i; i2++) {
            linkedHashSet.add(Long.valueOf(parcel.readLong()));
        }
        return new StudyableModelData.StudyFolder(j, linkedHashSet);
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new StudyableModelData.StudyFolder[i];
    }
}
