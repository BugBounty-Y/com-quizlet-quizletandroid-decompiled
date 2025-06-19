package com.google.android.exoplayer2.source;

import android.os.Parcel;
import android.os.Parcelable;
import android.support.v4.media.a;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class TrackGroupArray implements Parcelable {
    public static final Parcelable.Creator<TrackGroupArray> CREATOR = new a(20);
    public final int a;
    public final TrackGroup[] b;
    public int c;

    public TrackGroupArray(TrackGroup... trackGroupArr) {
        this.b = trackGroupArr;
        this.a = trackGroupArr.length;
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && TrackGroupArray.class == obj.getClass()) {
            TrackGroupArray trackGroupArray = (TrackGroupArray) obj;
            if (this.a == trackGroupArray.a && Arrays.equals(this.b, trackGroupArray.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        if (this.c == 0) {
            this.c = Arrays.hashCode(this.b);
        }
        return this.c;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        int i2 = this.a;
        parcel.writeInt(i2);
        for (int i3 = 0; i3 < i2; i3++) {
            parcel.writeParcelable(this.b[i3], 0);
        }
    }

    public TrackGroupArray(Parcel parcel) {
        int i = parcel.readInt();
        this.a = i;
        this.b = new TrackGroup[i];
        for (int i2 = 0; i2 < this.a; i2++) {
            this.b[i2] = (TrackGroup) parcel.readParcelable(TrackGroup.class.getClassLoader());
        }
    }
}
