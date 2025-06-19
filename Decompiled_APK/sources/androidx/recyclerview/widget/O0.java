package androidx.recyclerview.widget;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.recyclerview.widget.StaggeredGridLayoutManager;

/* loaded from: classes.dex */
public final class O0 implements Parcelable.Creator {
    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        StaggeredGridLayoutManager.SavedState savedState = new StaggeredGridLayoutManager.SavedState();
        savedState.a = parcel.readInt();
        savedState.b = parcel.readInt();
        int i = parcel.readInt();
        savedState.c = i;
        if (i > 0) {
            int[] iArr = new int[i];
            savedState.d = iArr;
            parcel.readIntArray(iArr);
        }
        int i2 = parcel.readInt();
        savedState.e = i2;
        if (i2 > 0) {
            int[] iArr2 = new int[i2];
            savedState.f = iArr2;
            parcel.readIntArray(iArr2);
        }
        savedState.h = parcel.readInt() == 1;
        savedState.i = parcel.readInt() == 1;
        savedState.j = parcel.readInt() == 1;
        savedState.g = parcel.readArrayList(StaggeredGridLayoutManager$LazySpanLookup$FullSpanItem.class.getClassLoader());
        return savedState;
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new StaggeredGridLayoutManager.SavedState[i];
    }
}
