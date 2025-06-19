package org.prebid.mobile.rendering.models.internal;

import org.prebid.mobile.rendering.models.ntv.NativeEventTracker$EventType;

/* loaded from: classes3.dex */
public class VisibilityTrackerOption {
    public NativeEventTracker$EventType a;
    public int b;
    public int c;
    public boolean d;
    public long e;

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null || getClass() != obj.getClass()) {
            return false;
        }
        VisibilityTrackerOption visibilityTrackerOption = (VisibilityTrackerOption) obj;
        return this.b == visibilityTrackerOption.b && this.c == visibilityTrackerOption.c && this.d == visibilityTrackerOption.d && this.e == visibilityTrackerOption.e && this.a == visibilityTrackerOption.a;
    }

    public final int hashCode() {
        NativeEventTracker$EventType nativeEventTracker$EventType = this.a;
        int iHashCode = (((((((nativeEventTracker$EventType != null ? nativeEventTracker$EventType.hashCode() : 0) * 31) + this.b) * 31) + this.c) * 31) + (this.d ? 1 : 0)) * 31;
        long j = this.e;
        return iHashCode + ((int) (j ^ (j >>> 32)));
    }
}
