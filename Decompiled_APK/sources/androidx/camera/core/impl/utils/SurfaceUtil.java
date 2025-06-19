package androidx.camera.core.impl.utils;

import android.view.Surface;
import com.google.android.gms.internal.mlkit_common.u;

/* loaded from: classes.dex */
public abstract class SurfaceUtil {
    static {
        System.loadLibrary("surface_util_jni");
    }

    public static u a(Surface surface) {
        int[] iArrNativeGetSurfaceInfo = nativeGetSurfaceInfo(surface);
        u uVar = new u(2);
        int i = iArrNativeGetSurfaceInfo[0];
        int i2 = iArrNativeGetSurfaceInfo[1];
        int i3 = iArrNativeGetSurfaceInfo[2];
        return uVar;
    }

    private static native int[] nativeGetSurfaceInfo(Surface surface);
}
