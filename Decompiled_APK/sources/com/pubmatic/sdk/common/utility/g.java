package com.pubmatic.sdk.common.utility;

import android.annotation.SuppressLint;
import android.content.Context;
import android.location.Address;
import android.location.Geocoder;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.os.Bundle;
import android.os.SystemClock;
import androidx.annotation.NonNull;
import com.pubmatic.sdk.common.log.POBLog;
import com.skydoves.balloon.internals.DefinitionKt;
import java.io.IOException;
import java.util.List;
import java.util.Locale;

/* loaded from: classes2.dex */
public class g implements LocationListener {

    @NonNull
    private final Context a;
    private Location b;
    private LocationManager c;
    private long d = 0;
    private long e = 600000;

    public enum a {
        NETWORK("network"),
        GPS("gps"),
        PASSIVE("passive");

        private final String e;

        a(String str) {
            this.e = str;
        }

        public boolean a(Context context) {
            int i = f.a[ordinal()];
            if (i == 1) {
                return o.hasPermission(context, "android.permission.ACCESS_FINE_LOCATION") || o.hasPermission(context, "android.permission.ACCESS_COARSE_LOCATION");
            }
            if (i == 2 || i == 3) {
                return o.hasPermission(context, "android.permission.ACCESS_FINE_LOCATION");
            }
            return false;
        }

        @Override // java.lang.Enum
        @NonNull
        public String toString() {
            return this.e;
        }
    }

    public g(@NonNull Context context) {
        this.a = context;
    }

    @SuppressLint({"MissingPermission"})
    private void a() {
        LocationManager locationManagerA = a(this.a);
        if (locationManagerA == null) {
            POBLog.info("PMLocationDetector", "Location Manager is not available to fetch GPS location", new Object[0]);
            return;
        }
        a aVar = a.NETWORK;
        if (!locationManagerA.isProviderEnabled(aVar.toString())) {
            aVar = a.GPS;
        }
        if (!aVar.a(this.a)) {
            POBLog.info("PMLocationDetector", "No permission to fetch GPS location", new Object[0]);
            return;
        }
        try {
            POBLog.info("PMLocationDetector", "Requesting %s location", aVar.toString());
            locationManagerA.requestLocationUpdates(aVar.toString(), 0L, DefinitionKt.NO_Float_VALUE, this);
        } catch (Exception e) {
            POBLog.info("PMLocationDetector", e.getLocalizedMessage(), new Object[0]);
        }
    }

    private boolean b() {
        return this.d == 0 || SystemClock.elapsedRealtime() - this.d >= this.e;
    }

    @SuppressLint({"MissingPermission"})
    private void c() {
        LocationManager locationManagerA = a(this.a);
        if (locationManagerA != null) {
            locationManagerA.removeUpdates(this);
        }
    }

    public Address getAddress() throws IOException {
        Location location = getLocation();
        if (location == null) {
            return null;
        }
        try {
            List<Address> fromLocation = new Geocoder(this.a, Locale.getDefault()).getFromLocation(location.getLatitude(), location.getLongitude(), 1);
            if (fromLocation == null || fromLocation.isEmpty()) {
                return null;
            }
            return fromLocation.get(0);
        } catch (IOException unused) {
            return null;
        }
    }

    public String getISOAlpha2CountryCode() throws IOException {
        Location location = getLocation();
        if (location == null) {
            return null;
        }
        try {
            List<Address> fromLocation = new Geocoder(this.a, Locale.getDefault()).getFromLocation(location.getLatitude(), location.getLongitude(), 1);
            if (fromLocation == null || fromLocation.isEmpty()) {
                return null;
            }
            return fromLocation.get(0).getCountryCode();
        } catch (IOException unused) {
            return null;
        }
    }

    public Location getLocation() {
        a aVar = a.GPS;
        if (!aVar.a(this.a) && !a.NETWORK.a(this.a)) {
            return null;
        }
        if (b()) {
            a();
            Location locationA = a(a(this.a, aVar), a(this.a, a.NETWORK));
            this.b = locationA;
            if (locationA == null) {
                this.b = a(this.a, a.PASSIVE);
            }
            if (this.b != null) {
                this.d = SystemClock.elapsedRealtime();
            }
            c();
        }
        return this.b;
    }

    @Override // android.location.LocationListener
    public void onLocationChanged(@NonNull Location location) {
        POBLog.info("PMLocationDetector", "On location changed : %s on time : %s", location.toString(), Long.valueOf(location.getTime()));
        this.b = location;
        c();
    }

    @Override // android.location.LocationListener
    public void onProviderDisabled(@NonNull String str) {
        POBLog.info("PMLocationDetector", "On location provider disabled", new Object[0]);
    }

    @Override // android.location.LocationListener
    public void onProviderEnabled(@NonNull String str) {
        POBLog.info("PMLocationDetector", "On location provider enabled", new Object[0]);
    }

    @Override // android.location.LocationListener
    public void onStatusChanged(String str, int i, Bundle bundle) {
        POBLog.info("PMLocationDetector", "On location provider status changed : %s", Integer.valueOf(i));
    }

    public void setLocationUpdateIntervalInMs(long j) {
        this.e = j;
    }

    @SuppressLint({"MissingPermission"})
    private Location a(Context context, a aVar) {
        LocationManager locationManagerA;
        if (aVar.a(context) && (locationManagerA = a(context)) != null) {
            try {
                this.b = locationManagerA.getLastKnownLocation(aVar.toString());
            } catch (IllegalArgumentException e) {
                POBLog.error("PMLocationDetector", "Unable to fetch the location.", "Error : " + e.getLocalizedMessage());
            } catch (SecurityException unused) {
                POBLog.error("PMLocationDetector", "Unable to fetch the location as user has restricted/denied location access to this app.", new Object[0]);
            } catch (Exception e2) {
                POBLog.error("PMLocationDetector", "Unable to fetch the location due to unknown reason.", "Error : " + e2.getLocalizedMessage());
            }
        }
        return this.b;
    }

    private Location a(Location location, Location location2) {
        return location == null ? location2 : (location2 != null && location.getTime() <= location2.getTime()) ? location2 : location;
    }

    private LocationManager a(@NonNull Context context) {
        if (this.c == null) {
            this.c = (LocationManager) context.getSystemService("location");
        }
        return this.c;
    }
}
