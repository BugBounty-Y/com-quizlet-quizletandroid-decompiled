package com.quizlet.features.infra.studysetting.data;

import android.os.Parcel;
import android.os.Parcelable;
import assistantMode.enums.y;
import com.quizlet.generated.enums.O1;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class a implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ a(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        boolean z;
        boolean z2;
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new GradingSettingsValues(parcel.readInt() != 0, parcel.readInt() != 0, parcel.readInt() != 0);
            case 1:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                int i = parcel.readInt();
                ArrayList arrayList = new ArrayList(i);
                for (int i2 = 0; i2 != i; i2++) {
                    arrayList.add(O1.valueOf(parcel.readString()));
                }
                int i3 = parcel.readInt();
                ArrayList arrayList2 = new ArrayList(i3);
                for (int i4 = 0; i4 != i3; i4++) {
                    arrayList2.add(O1.valueOf(parcel.readString()));
                }
                boolean z3 = true;
                if (parcel.readInt() != 0) {
                    z = true;
                } else {
                    z = true;
                    z3 = false;
                }
                return new QuestionSettings(arrayList, arrayList2, z3, parcel.readInt() != 0 ? z : false, parcel.readInt() != 0 ? z : false, parcel.readInt() != 0 ? z : false, parcel.readInt() != 0 ? z : false, parcel.readInt() != 0 ? z : false, parcel.readInt() != 0 ? z : false, parcel.readInt() == 0 ? null : Long.valueOf(parcel.readLong()), parcel.readInt() == 0 ? null : Long.valueOf(parcel.readLong()), parcel.readInt() == 0 ? null : com.quizlet.studiablemodels.assistantMode.a.valueOf(parcel.readString()), parcel.readInt() != 0 ? y.valueOf(parcel.readString()) : null, parcel.readInt() != 0 ? z : false, parcel.readInt() != 0 ? z : false, parcel.readInt() != 0 ? z : false, parcel.readInt() != 0 ? z : false, parcel.readInt() != 0 ? z : false);
            default:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                int i5 = parcel.readInt();
                int i6 = parcel.readInt();
                ArrayList arrayList3 = new ArrayList(i6);
                for (int i7 = 0; i7 != i6; i7++) {
                    arrayList3.add(O1.valueOf(parcel.readString()));
                }
                int i8 = parcel.readInt();
                ArrayList arrayList4 = new ArrayList(i8);
                for (int i9 = 0; i9 != i8; i9++) {
                    arrayList4.add(O1.valueOf(parcel.readString()));
                }
                int i10 = parcel.readInt();
                LinkedHashSet linkedHashSet = new LinkedHashSet(i10);
                for (int i11 = 0; i11 != i10; i11++) {
                    linkedHashSet.add(com.quizlet.sharedconfig.study_setting_metadata.b.valueOf(parcel.readString()));
                }
                boolean z4 = true;
                if (parcel.readInt() != 0) {
                    z2 = true;
                } else {
                    z2 = true;
                    z4 = false;
                }
                return new TestStudyModeConfig(i5, arrayList3, arrayList4, linkedHashSet, z4, parcel.readInt() != 0 ? z2 : false, parcel.readInt() != 0 ? z2 : false, parcel.readInt() != 0 ? z2 : false);
        }
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new GradingSettingsValues[i];
            case 1:
                return new QuestionSettings[i];
            default:
                return new TestStudyModeConfig[i];
        }
    }
}
