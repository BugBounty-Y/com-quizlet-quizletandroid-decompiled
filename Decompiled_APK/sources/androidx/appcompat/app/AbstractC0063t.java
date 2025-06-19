package androidx.appcompat.app;

import android.os.PowerManager;
import java.util.Locale;

/* renamed from: androidx.appcompat.app.t, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0063t {
    public static boolean a(PowerManager powerManager) {
        return powerManager.isPowerSaveMode();
    }

    public static String b(Locale locale) {
        return locale.toLanguageTag();
    }
}
