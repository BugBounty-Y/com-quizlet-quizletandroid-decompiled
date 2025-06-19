package org.greenrobot.eventbus.android;

/* loaded from: classes3.dex */
public class AndroidComponentsImpl {
    static {
        try {
            if (Class.forName("android.os.Looper").getDeclaredMethod("getMainLooper", null).invoke(null, null) != null) {
            }
        } catch (Throwable unused) {
        }
    }
}
