package com.quizlet.uicommon.ui.common.dialogs.info;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.uicommon.ui.common.dialogs.info.InfoModalButtonState;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class e implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        parcel.readInt();
        return InfoModalButtonState.Secondary.a;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new InfoModalButtonState.Secondary[i];
    }
}
