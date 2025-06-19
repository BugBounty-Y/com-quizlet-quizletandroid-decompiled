package org.prebid.mobile.rendering.models.internal;

import org.prebid.mobile.rendering.models.ntv.NativeEventTracker$EventType;
import org.prebid.mobile.rendering.utils.exposure.ViewExposure;

/* loaded from: classes3.dex */
public class VisibilityTrackerResult {
    public final NativeEventTracker$EventType a;
    public final ViewExposure b;
    public final boolean c;
    public final boolean d;

    public VisibilityTrackerResult(NativeEventTracker$EventType nativeEventTracker$EventType, ViewExposure viewExposure, boolean z, boolean z2) {
        this.a = nativeEventTracker$EventType;
        this.b = viewExposure;
        this.c = z;
        this.d = z2;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj != null && getClass() == obj.getClass()) {
            VisibilityTrackerResult visibilityTrackerResult = (VisibilityTrackerResult) obj;
            if (this.c != visibilityTrackerResult.c || this.d != visibilityTrackerResult.d || this.a != visibilityTrackerResult.a) {
                return false;
            }
            ViewExposure viewExposure = visibilityTrackerResult.b;
            ViewExposure viewExposure2 = this.b;
            if (viewExposure2 != null) {
                return viewExposure2.equals(viewExposure);
            }
            if (viewExposure == null) {
                return true;
            }
        }
        return false;
    }

    public final int hashCode() {
        NativeEventTracker$EventType nativeEventTracker$EventType = this.a;
        int iHashCode = (nativeEventTracker$EventType != null ? nativeEventTracker$EventType.hashCode() : 0) * 31;
        ViewExposure viewExposure = this.b;
        return ((((iHashCode + (viewExposure != null ? viewExposure.hashCode() : 0)) * 31) + (this.c ? 1 : 0)) * 31) + (this.d ? 1 : 0);
    }
}
