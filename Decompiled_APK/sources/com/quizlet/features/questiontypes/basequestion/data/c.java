package com.quizlet.features.questiontypes.basequestion.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.FillInTheBlankStudiableQuestion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new ShowQuestion.FillInTheBlank((FillInTheBlankStudiableQuestion) parcel.readParcelable(ShowQuestion.FillInTheBlank.class.getClassLoader()), parcel.readLong(), parcel.readLong(), (QuestionSettings) parcel.readParcelable(ShowQuestion.FillInTheBlank.class.getClassLoader()), A1.valueOf(parcel.readString()));
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ShowQuestion.FillInTheBlank[i];
    }
}
