package com.google.android.exoplayer2.source;

import android.os.Parcel;
import android.os.Parcelable;
import android.support.v4.media.a;
import com.google.android.exoplayer2.Format;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class TrackGroup implements Parcelable {
    public static final Parcelable.Creator<TrackGroup> CREATOR = new a(19);
    public final int a;
    public final Format[] b;
    public int c;

    public TrackGroup(Parcel parcel) {
        int i = parcel.readInt();
        this.a = i;
        this.b = new Format[i];
        for (int i2 = 0; i2 < this.a; i2++) {
            this.b[i2] = (Format) parcel.readParcelable(Format.class.getClassLoader());
        }
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && TrackGroup.class == obj.getClass()) {
            TrackGroup trackGroup = (TrackGroup) obj;
            if (this.a == trackGroup.a && Arrays.equals(this.b, trackGroup.b)) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        if (this.c == 0) {
            this.c = 527 + Arrays.hashCode(this.b);
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
}
