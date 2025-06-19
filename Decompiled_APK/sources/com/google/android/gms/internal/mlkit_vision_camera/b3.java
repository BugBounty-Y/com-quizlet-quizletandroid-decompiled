package com.google.android.gms.internal.mlkit_vision_camera;

/* loaded from: classes2.dex */
public final class b3 {
    public final boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (!(obj instanceof b3)) {
            return false;
        }
        ((b3) obj).getClass();
        return true;
    }

    public final int hashCode() {
        return 581378486;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder(90);
        sb.append("MLKitLoggingOptions{libraryName=camera, enableFirelog=true, firelogEventType=1}");
        return sb.toString();
    }
}
