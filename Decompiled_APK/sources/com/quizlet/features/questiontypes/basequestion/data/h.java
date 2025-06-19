package com.quizlet.features.questiontypes.basequestion.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.data.model.InterfaceC4176w0;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.features.questiontypes.basequestion.data.ShowQuestion;
import com.quizlet.generated.enums.A1;
import com.quizlet.studiablemodels.WrittenStudiableQuestion;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class h implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        boolean z;
        InterfaceC4176w0 interfaceC4176w0;
        boolean z2;
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        WrittenStudiableQuestion writtenStudiableQuestion = (WrittenStudiableQuestion) parcel.readParcelable(ShowQuestion.Written.class.getClassLoader());
        long j = parcel.readLong();
        long j2 = parcel.readLong();
        QuestionSettings questionSettings = (QuestionSettings) parcel.readParcelable(ShowQuestion.Written.class.getClassLoader());
        A1 a1ValueOf = A1.valueOf(parcel.readString());
        boolean z3 = false;
        if (parcel.readInt() != 0) {
            z = false;
            z3 = true;
        } else {
            z = false;
        }
        InterfaceC4176w0 interfaceC4176w02 = (InterfaceC4176w0) parcel.readSerializable();
        if (parcel.readInt() != 0) {
            z2 = true;
            interfaceC4176w0 = interfaceC4176w02;
        } else {
            interfaceC4176w0 = interfaceC4176w02;
            z2 = z;
        }
        return new ShowQuestion.Written(writtenStudiableQuestion, j, j2, questionSettings, a1ValueOf, z3, interfaceC4176w0, z2);
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ShowQuestion.Written[i];
    }
}
