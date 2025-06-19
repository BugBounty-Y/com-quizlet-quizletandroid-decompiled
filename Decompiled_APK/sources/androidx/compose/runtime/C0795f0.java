package androidx.compose.runtime;

import android.os.Parcel;
import android.os.Parcelable;
import androidx.camera.camera2.internal.AbstractC0147y;

/* renamed from: androidx.compose.runtime.f0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C0795f0 implements Parcelable.ClassLoaderCreator {
    public static ParcelableSnapshotMutableState a(Parcel parcel, ClassLoader classLoader) {
        V v;
        if (classLoader == null) {
            classLoader = C0795f0.class.getClassLoader();
        }
        Object value = parcel.readValue(classLoader);
        int i = parcel.readInt();
        if (i == 0) {
            v = V.c;
        } else if (i == 1) {
            v = V.f;
        } else {
            if (i != 2) {
                throw new IllegalStateException(AbstractC0147y.c(i, "Unsupported MutableState policy ", " was restored"));
            }
            v = V.d;
        }
        return new ParcelableSnapshotMutableState(value, v);
    }

    @Override // android.os.Parcelable.ClassLoaderCreator
    public final /* bridge */ /* synthetic */ Object createFromParcel(Parcel parcel, ClassLoader classLoader) {
        return a(parcel, classLoader);
    }

    @Override // android.os.Parcelable.Creator
    public final Object[] newArray(int i) {
        return new ParcelableSnapshotMutableState[i];
    }

    @Override // android.os.Parcelable.Creator
    public final Object createFromParcel(Parcel parcel) {
        return a(parcel, null);
    }
}
