package org.prebid.mobile.rendering.networking.tracking;

/* loaded from: classes3.dex */
public class TrackingManager {
    public static TrackingManager a;

    private TrackingManager() {
    }

    public static TrackingManager a() {
        if (a == null) {
            a = new TrackingManager();
        }
        return a;
    }
}
