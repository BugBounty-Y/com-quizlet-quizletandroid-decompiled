package com.google.firebase.perf.util;

import android.os.Parcel;
import android.os.Parcelable;
import android.os.SystemClock;
import com.google.android.gms.fido.fido2.api.common.i;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public class Timer implements Parcelable {
    public static final Parcelable.Creator<Timer> CREATOR = new i(28);
    public long a;
    public long b;

    public Timer() {
        this(TimeUnit.MILLISECONDS.toMicros(System.currentTimeMillis()), TimeUnit.NANOSECONDS.toMicros(SystemClock.elapsedRealtimeNanos()));
    }

    public final long a() {
        return new Timer().b - this.b;
    }

    public final long b(Timer timer) {
        return timer.b - this.b;
    }

    public final void c() {
        this.a = TimeUnit.MILLISECONDS.toMicros(System.currentTimeMillis());
        this.b = TimeUnit.NANOSECONDS.toMicros(SystemClock.elapsedRealtimeNanos());
    }

    @Override // android.os.Parcelable
    public final int describeContents() {
        return 0;
    }

    @Override // android.os.Parcelable
    public final void writeToParcel(Parcel parcel, int i) {
        parcel.writeLong(this.a);
        parcel.writeLong(this.b);
    }

    public Timer(long j, long j2) {
        this.a = j;
        this.b = j2;
    }
}
