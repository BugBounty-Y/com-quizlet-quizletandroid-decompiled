package androidx.appcompat.app;

import android.content.res.Configuration;
import android.os.LocaleList;
import androidx.annotation.NonNull;

/* loaded from: classes.dex */
public abstract class u {
    public static void a(@NonNull Configuration configuration, @NonNull Configuration configuration2, @NonNull Configuration configuration3) {
        LocaleList locales = configuration.getLocales();
        LocaleList locales2 = configuration2.getLocales();
        if (locales.equals(locales2)) {
            return;
        }
        configuration3.setLocales(locales2);
        configuration3.locale = configuration2.locale;
    }

    public static androidx.core.os.f b(Configuration configuration) {
        return androidx.core.os.f.a(configuration.getLocales().toLanguageTags());
    }

    public static void c(androidx.core.os.f fVar) {
        LocaleList.setDefault(LocaleList.forLanguageTags(fVar.a.a.toLanguageTags()));
    }

    public static void d(Configuration configuration, androidx.core.os.f fVar) {
        configuration.setLocales(LocaleList.forLanguageTags(fVar.a.a.toLanguageTags()));
    }
}
