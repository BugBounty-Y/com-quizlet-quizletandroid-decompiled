package com.quizlet.studiablemodels.grading;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.billing.subscriptions.j;
import com.quizlet.studiablemodels.StudiableMeteringData;
import com.quizlet.upgrade.data.UpgradePackage;
import java.util.ArrayList;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements Parcelable.Creator {
    public final /* synthetic */ int a;

    public /* synthetic */ e(int i) {
        this.a = i;
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        switch (this.a) {
            case 0:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                double d = parcel.readDouble();
                int i = parcel.readInt();
                ArrayList arrayList = new ArrayList(i);
                for (int i2 = 0; i2 != i; i2++) {
                    arrayList.add(StudiableQuestionGradedAnswer.CREATOR.createFromParcel(parcel));
                }
                return new StudiableTestResults(d, arrayList, parcel.readInt() == 0 ? null : StudiableMeteringData.CREATOR.createFromParcel(parcel));
            case 1:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new TrueFalseResponse(parcel.readInt() != 0);
            case 2:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new WrittenResponse(parcel.readString());
            default:
                Intrinsics.checkNotNullParameter(parcel, "parcel");
                return new UpgradePackage(j.valueOf(parcel.readString()));
        }
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        switch (this.a) {
            case 0:
                return new StudiableTestResults[i];
            case 1:
                return new TrueFalseResponse[i];
            case 2:
                return new WrittenResponse[i];
            default:
                return new UpgradePackage[i];
        }
    }
}
