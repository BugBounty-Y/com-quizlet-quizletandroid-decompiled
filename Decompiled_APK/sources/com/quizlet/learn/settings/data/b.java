package com.quizlet.learn.settings.data;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.features.infra.studysetting.data.QuestionSettings;
import com.quizlet.learn.settings.data.LearnSettingsResult;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        boolean z;
        boolean z2;
        boolean z3;
        boolean z4;
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        QuestionSettings questionSettings = (QuestionSettings) parcel.readParcelable(LearnSettingsResult.Updated.class.getClassLoader());
        boolean z5 = false;
        boolean z6 = true;
        if (parcel.readInt() != 0) {
            z = false;
            z5 = true;
        } else {
            z = false;
        }
        if (parcel.readInt() != 0) {
            z2 = true;
        } else {
            z2 = true;
            z6 = z;
        }
        if (parcel.readInt() != 0) {
            z3 = z2;
        } else {
            z3 = z2;
            z2 = z;
        }
        if (parcel.readInt() != 0) {
            z4 = z3;
        } else {
            z4 = z3;
            z3 = z;
        }
        if (parcel.readInt() == 0) {
            z4 = z;
        }
        return new LearnSettingsResult.Updated(questionSettings, z5, z6, z2, z3, z4);
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new LearnSettingsResult.Updated[i];
    }
}
