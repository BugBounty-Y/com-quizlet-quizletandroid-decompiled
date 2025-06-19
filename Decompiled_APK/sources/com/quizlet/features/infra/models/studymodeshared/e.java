package com.quizlet.features.infra.models.studymodeshared;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new StudyableModelData.StudySet(parcel.readLong());
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new StudyableModelData.StudySet[i];
    }
}
