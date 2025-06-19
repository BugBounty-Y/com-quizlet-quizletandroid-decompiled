package androidx.camera.core.impl;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import androidx.activity.AbstractC0029a;
import androidx.camera.core.C0192o;
import com.google.android.gms.internal.measurement.AbstractC3053s1;
import java.util.LinkedHashSet;

/* loaded from: classes.dex */
public abstract class E {
    public static final C0192o a;

    static {
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        linkedHashSet.add(new T(2));
        a = new C0192o(linkedHashSet);
    }

    public static void a(Context context, com.quizlet.data.interactor.school.b bVar, C0192o c0192o) throws CameraValidator$CameraIdListIncorrectException {
        Integer numB;
        int i = 0;
        IllegalArgumentException illegalArgumentException = null;
        if (Build.VERSION.SDK_INT >= 34 && AbstractC0029a.f(context) != 0) {
            LinkedHashSet linkedHashSetK = bVar.k();
            if (linkedHashSetK.isEmpty()) {
                throw new CameraValidator$CameraIdListIncorrectException("No cameras available", 0, null);
            }
            AbstractC0029a.f(context);
            linkedHashSetK.size();
            AbstractC3053s1.f(3, "CameraValidator");
            return;
        }
        if (c0192o != null) {
            try {
                numB = c0192o.b();
                if (numB == null) {
                    AbstractC3053s1.h("CameraValidator", "No lens facing info in the availableCamerasSelector, don't verify the camera lens facing.");
                    return;
                }
            } catch (IllegalStateException e) {
                AbstractC3053s1.d("CameraValidator", "Cannot get lens facing from the availableCamerasSelector don't verify the camera lens facing.", e);
                return;
            }
        } else {
            numB = null;
        }
        String str = Build.DEVICE;
        AbstractC3053s1.f(3, "CameraValidator");
        PackageManager packageManager = context.getPackageManager();
        try {
            if (packageManager.hasSystemFeature("android.hardware.camera") && (c0192o == null || numB.intValue() == 1)) {
                C0192o.c.c(bVar.k());
                i = 1;
            }
        } catch (IllegalArgumentException e2) {
            illegalArgumentException = e2;
            AbstractC3053s1.i("CameraValidator", "Camera LENS_FACING_BACK verification failed", illegalArgumentException);
        }
        try {
            if (packageManager.hasSystemFeature("android.hardware.camera.front") && (c0192o == null || numB.intValue() == 0)) {
                C0192o.b.c(bVar.k());
                i++;
            }
        } catch (IllegalArgumentException e3) {
            illegalArgumentException = e3;
            AbstractC3053s1.i("CameraValidator", "Camera LENS_FACING_FRONT verification failed", illegalArgumentException);
        }
        try {
            a.c(bVar.k());
            AbstractC3053s1.f(3, "CameraValidator");
            i++;
        } catch (IllegalArgumentException unused) {
        }
        if (illegalArgumentException == null) {
            return;
        }
        AbstractC3053s1.c("CameraValidator", "Camera LensFacing verification failed, existing cameras: " + bVar.k());
        throw new CameraValidator$CameraIdListIncorrectException("Expected camera missing from device.", i, illegalArgumentException);
    }
}
