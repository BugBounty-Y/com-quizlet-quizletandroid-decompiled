package com.quizlet.learn.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.features.infra.models.studymodeshared.StudyableModelData;
import com.quizlet.learn.data.LearnRoundSummaryData;
import com.quizlet.studiablemodels.AssistantCheckpointProgressState;
import com.quizlet.studiablemodels.StudiableTaskProgress;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class w implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        StudyableModelData studyableModelData = (StudyableModelData) parcel.readParcelable(LearnRoundSummaryData.TaskCompletedCheckpointData.class.getClassLoader());
        String string = parcel.readString();
        int i = parcel.readInt();
        ArrayList arrayList = new ArrayList(i);
        for (int i2 = 0; i2 != i; i2++) {
            arrayList.add(parcel.readParcelable(LearnRoundSummaryData.TaskCompletedCheckpointData.class.getClassLoader()));
        }
        return new LearnRoundSummaryData.TaskCompletedCheckpointData(studyableModelData, string, arrayList, (AssistantCheckpointProgressState) parcel.readParcelable(LearnRoundSummaryData.TaskCompletedCheckpointData.class.getClassLoader()), (StudiableTaskProgress) parcel.readParcelable(LearnRoundSummaryData.TaskCompletedCheckpointData.class.getClassLoader()), parcel.readInt());
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new LearnRoundSummaryData.TaskCompletedCheckpointData[i];
    }
}
