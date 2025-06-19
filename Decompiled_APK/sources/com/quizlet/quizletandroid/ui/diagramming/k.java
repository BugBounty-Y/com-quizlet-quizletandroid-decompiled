package com.quizlet.quizletandroid.ui.diagramming;

import android.os.Parcel;
import android.os.Parcelable;
import com.quizlet.quizletandroid.ui.diagramming.DiagramView;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class k implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        long[] jArrCreateLongArray;
        Intrinsics.checkNotNullParameter(parcel, "parcel");
        DiagramView.SavedState savedState = new DiagramView.SavedState(parcel);
        savedState.a = new long[0];
        if (parcel == null || (jArrCreateLongArray = parcel.createLongArray()) == null) {
            jArrCreateLongArray = new long[0];
        }
        savedState.a = jArrCreateLongArray;
        return savedState;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new DiagramView.SavedState[i];
    }
}
