package com.amazon.device.ads;

import android.util.DisplayMetrics;
import android.view.WindowManager;
import java.util.HashSet;

/* loaded from: classes.dex */
class AdUtils {
    public static final String REQUIRED_ACTIVITY = "com.amazon.device.ads.AdActivity";
    private static AdUtilsExecutor executor = new AdUtilsExecutor();

    public static class AdUtilsExecutor {
        private boolean hasRequiredActivities;
        private final HashSet<String> requiredActivities;

        public AdUtilsExecutor() {
            HashSet<String> hashSet = new HashSet<>();
            this.requiredActivities = hashSet;
            this.hasRequiredActivities = false;
            hashSet.add(AdUtils.REQUIRED_ACTIVITY);
        }

        public double calculateScalingMultiplier(int i, int i2, int i3, int i4) {
            double d = i3 / i;
            double d2 = i4 / i2;
            if ((d2 < d || d == 0.0d) && d2 != 0.0d) {
                d = d2;
            }
            if (d == 0.0d) {
                return 1.0d;
            }
            return d;
        }

        public int deviceIndependentPixelToPixel(int i) {
            return (int) (i == -1 ? i : i * getScalingFactorAsFloat());
        }

        public float getScalingFactorAsFloat() {
            WindowManager windowManager = (WindowManager) AdRegistration.getContext().getSystemService("window");
            DisplayMetrics displayMetrics = new DisplayMetrics();
            windowManager.getDefaultDisplay().getMetrics(displayMetrics);
            return displayMetrics.scaledDensity;
        }

        public int pixelToDeviceIndependentPixel(int i) {
            return (int) (i / getScalingFactorAsFloat());
        }
    }

    private AdUtils() {
    }

    public static double calculateScalingMultiplier(int i, int i2, int i3, int i4) {
        return executor.calculateScalingMultiplier(i, i2, i3, i4);
    }

    public static int deviceIndependentPixelToPixel(int i) {
        return executor.deviceIndependentPixelToPixel(i);
    }

    public static float getScalingFactorAsFloat() {
        return executor.getScalingFactorAsFloat();
    }

    public static int pixelToDeviceIndependentPixel(int i) {
        return executor.pixelToDeviceIndependentPixel(i);
    }
}
