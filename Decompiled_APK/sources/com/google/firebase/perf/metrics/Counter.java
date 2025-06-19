package com.google.firebase.perf.metrics;

import android.os.Parcel;
import android.os.Parcelable;
import com.google.android.gms.fido.fido2.api.common.i;
import java.util.concurrent.atomic.AtomicLong;

/* loaded from: classes2.dex */
public class Counter implements Parcelable {
    public static final Parcelable.Creator<Counter> CREATOR = new i(25);
    public final String a;
    public final AtomicLong b;

    public Counter(String str) {
        this.a = str;
        this.b = new AtomicLong(0L);
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeString(this.a);
        parcel.writeLong(this.b.get());
    }

    public Counter(Parcel parcel) {
        this.a = parcel.readString();
        this.b = new AtomicLong(parcel.readLong());
    }
}
