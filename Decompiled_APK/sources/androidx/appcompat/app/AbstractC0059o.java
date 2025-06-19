package androidx.appcompat.app;

import android.app.LocaleManager;
import android.os.LocaleList;

/* renamed from: androidx.appcompat.app.o, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC0059o {
    public static LocaleList a(Object obj) {
        return ((LocaleManager) obj).getApplicationLocales();
    }

    public static void b(Object obj, LocaleList localeList) {
        ((LocaleManager) obj).setApplicationLocales(localeList);
    }
}
