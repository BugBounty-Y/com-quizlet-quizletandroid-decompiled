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
public final class v implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        StudyableModelData studyableModelData = (StudyableModelData) parcel.readParcelable(LearnRoundSummaryData.RoundCheckpointData.class.getClassLoader());
        String string = parcel.readString();
        int i = parcel.readInt();
        ArrayList arrayList = new ArrayList(i);
        for (int i2 = 0; i2 != i; i2++) {
            arrayList.add(parcel.readParcelable(LearnRoundSummaryData.RoundCheckpointData.class.getClassLoader()));
        }
        AssistantCheckpointProgressState assistantCheckpointProgressState = (AssistantCheckpointProgressState) parcel.readParcelable(LearnRoundSummaryData.RoundCheckpointData.class.getClassLoader());
        StudiableTaskProgress studiableTaskProgress = (StudiableTaskProgress) parcel.readParcelable(LearnRoundSummaryData.RoundCheckpointData.class.getClassLoader());
        int i3 = parcel.readInt();
        int i4 = parcel.readInt();
        int i5 = parcel.readInt();
        int i6 = parcel.readInt();
        ArrayList arrayList2 = new ArrayList(i6);
        for (int i7 = 0; i7 != i6; i7++) {
            arrayList2.add(assistantMode.enums.k.valueOf(parcel.readString()));
        }
        return new LearnRoundSummaryData.RoundCheckpointData(studyableModelData, string, arrayList, assistantCheckpointProgressState, studiableTaskProgress, i3, i4, i5, arrayList2, parcel.readInt() != 0);
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new LearnRoundSummaryData.RoundCheckpointData[i];
    }
}
