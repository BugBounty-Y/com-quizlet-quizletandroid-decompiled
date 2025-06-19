package com.quizlet.features.questiontypes.basequestion.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.RevealSelfAssessmentStudiableQuestion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class f implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        return new ShowQuestion.SelfAssessment((RevealSelfAssessmentStudiableQuestion) parcel.readParcelable(ShowQuestion.SelfAssessment.class.getClassLoader()), parcel.readLong(), parcel.readLong(), (QuestionSettings) parcel.readParcelable(ShowQuestion.SelfAssessment.class.getClassLoader()), A1.valueOf(parcel.readString()));
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ShowQuestion.SelfAssessment[i];
    }
}
