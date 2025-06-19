package com.braze.models;

import androidx.compose.animation.d0;
import com.comscore.util.log.LogLevel;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.x;
import org.json.JSONException;
import org.json.JSONObject;

@Metadata
/* loaded from: classes.dex */
public final class BrazeGeofence implements IPutIntoJson<JSONObject>, Comparable<BrazeGeofence> {
    public static final c Companion = new c();
    private final boolean analyticsEnabledEnter;
    private final boolean analyticsEnabledExit;
    private final int cooldownEnterSeconds;
    private final int cooldownExitSeconds;
    private double distanceFromGeofenceRefresh;
    private final boolean enterEvents;
    private final boolean exitEvents;
    private final String id;
    private final JSONObject jsonObject;
    private final double latitude;
    private final double longitude;
    private final int notificationResponsivenessMs;
    private final int radiusMeter;

    public BrazeGeofence(JSONObject jsonObject, String id, double d, double d2, int i, int i2, int i3, boolean z, boolean z2, boolean z3, boolean z4, int i4) {
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        Intrinsics.checkNotNullParameter(id, "id");
        this.jsonObject = jsonObject;
        this.id = id;
        this.latitude = d;
        this.longitude = d2;
        this.radiusMeter = i;
        this.cooldownEnterSeconds = i2;
        this.cooldownExitSeconds = i3;
        this.analyticsEnabledEnter = z;
        this.analyticsEnabledExit = z2;
        this.enterEvents = z3;
        this.exitEvents = z4;
        this.notificationResponsivenessMs = i4;
        this.distanceFromGeofenceRefresh = -1.0d;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!BrazeGeofence.class.equals(obj != null ? obj.getClass() : null)) {
            return false;
        }
        Intrinsics.e(obj, "null cannot be cast to non-null type com.braze.models.BrazeGeofence");
        BrazeGeofence brazeGeofence = (BrazeGeofence) obj;
        return Intrinsics.b(this.id, brazeGeofence.id) && this.latitude == brazeGeofence.latitude && this.longitude == brazeGeofence.longitude && this.radiusMeter == brazeGeofence.radiusMeter && this.cooldownEnterSeconds == brazeGeofence.cooldownEnterSeconds && this.cooldownExitSeconds == brazeGeofence.cooldownExitSeconds && this.analyticsEnabledEnter == brazeGeofence.analyticsEnabledEnter && this.analyticsEnabledExit == brazeGeofence.analyticsEnabledExit && this.enterEvents == brazeGeofence.enterEvents && this.exitEvents == brazeGeofence.exitEvents && this.notificationResponsivenessMs == brazeGeofence.notificationResponsivenessMs;
    }

    public final String getId() {
        return this.id;
    }

    public final double getRadiusMeters() {
        return this.radiusMeter;
    }

    public int hashCode() {
        return Double.hashCode(getRadiusMeters()) + ((d0.g(d0.g(d0.g(d0.g((((((d0.a(this.longitude, d0.a(this.latitude, d0.e(this.jsonObject.hashCode() * 31, 31, this.id), 31), 31) + this.radiusMeter) * 31) + this.cooldownEnterSeconds) * 31) + this.cooldownExitSeconds) * 31, 31, this.analyticsEnabledEnter), 31, this.analyticsEnabledExit), 31, this.enterEvents), 31, this.exitEvents) + this.notificationResponsivenessMs) * 31);
    }

    public String toString() {
        return x.d("BrazeGeofence{id=" + this.id + ", \n            |latitude, longitude=(" + this.latitude + ", " + this.longitude + "),\n            |radiusMeters=" + this.radiusMeter + ", \n            |cooldownEnterSeconds=" + this.cooldownEnterSeconds + ", \n            |cooldownExitSeconds=" + this.cooldownExitSeconds + ", \n            |analyticsEnabledEnter=" + this.analyticsEnabledEnter + ", \n            |analyticsEnabledExit=" + this.analyticsEnabledExit + ", \n            |enterEvents=" + this.enterEvents + ", \n            |exitEvents=" + this.exitEvents + ", \n            |notificationResponsivenessMs=" + this.notificationResponsivenessMs + ", \n            |distanceFromGeofenceRefresh=" + this.distanceFromGeofenceRefresh + " }\n            |\n        ");
    }

    @Override // java.lang.Comparable
    public int compareTo(BrazeGeofence other) {
        Intrinsics.checkNotNullParameter(other, "other");
        double d = this.distanceFromGeofenceRefresh;
        return (d != -1.0d && d < other.distanceFromGeofenceRefresh) ? -1 : 1;
    }

    @Override // com.braze.models.IPutIntoJson
    public JSONObject forJsonPut() {
        return this.jsonObject;
    }

    /* JADX WARN: Illegal instructions before constructor call */
    public BrazeGeofence(JSONObject jsonObject) throws JSONException {
        Intrinsics.checkNotNullParameter(jsonObject, "jsonObject");
        String string = jsonObject.getString("id");
        Intrinsics.checkNotNullExpressionValue(string, "getString(...)");
        this(jsonObject, string, jsonObject.getDouble("latitude"), jsonObject.getDouble("longitude"), jsonObject.getInt("radius"), jsonObject.getInt("cooldown_enter"), jsonObject.getInt("cooldown_exit"), jsonObject.getBoolean("analytics_enabled_enter"), jsonObject.getBoolean("analytics_enabled_exit"), jsonObject.optBoolean("enter_events", true), jsonObject.optBoolean("exit_events", true), jsonObject.optInt("notification_responsiveness", LogLevel.NONE));
    }
}
