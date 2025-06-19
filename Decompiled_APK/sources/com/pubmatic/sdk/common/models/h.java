package com.pubmatic.sdk.common.models;

import android.location.Location;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;

/* loaded from: classes2.dex */
public class h {
    private long a;
    private float b;
    private double c;
    private double d;
    private a e;

    public enum a {
        GPS(1),
        IP_ADDRESS(2),
        USER(3);

        private final int b;

        a(int i) {
            this.b = i;
        }

        public int getValue() {
            return this.b;
        }
    }

    public h(@NonNull a aVar, double d, double d2) {
        this.e = aVar;
        this.c = d;
        this.d = d2;
    }

    public float getAccuracy() {
        return this.b;
    }

    public long getLastFixInMillis() {
        return this.a;
    }

    public double getLatitude() {
        return this.c;
    }

    public double getLongitude() {
        return this.d;
    }

    public a getSource() {
        return this.e;
    }

    public h(@NonNull Location location) {
        if (location != null) {
            this.c = location.getLatitude();
            this.d = location.getLongitude();
            String provider = location.getProvider();
            if (provider != null && (provider.equalsIgnoreCase("network") || provider.equalsIgnoreCase("gps") || provider.equalsIgnoreCase("wifi"))) {
                this.e = a.GPS;
            } else {
                this.e = a.USER;
            }
            this.b = location.getAccuracy();
            this.a = (SystemClock.elapsedRealtimeNanos() - location.getElapsedRealtimeNanos()) / 1000000;
            return;
        }
        POBLog.debug("POBLocation", "Provided location object is null", new Object[0]);
    }
}
