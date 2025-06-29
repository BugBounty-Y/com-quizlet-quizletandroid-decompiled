package androidx.viewpager.widget;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.viewpager.widget.ViewPager;

/* loaded from: classes.dex */
public final class g implements Parcelable.ClassLoaderCreator {
    @Override // android.os.Parcelable.ClassLoaderCreator
    public final Object createFromParcel(Parcel parcel, ClassLoader classLoader) {
        return new ViewPager.SavedState(parcel, classLoader);
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ViewPager.SavedState[i];
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        return new ViewPager.SavedState(parcel, null);
    }
}
