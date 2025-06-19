package androidx.browser.customtabs;

import android.os.LocaleList;

/* loaded from: classes.dex */
public abstract class i {
    public static String a() {
        LocaleList adjustedDefault = LocaleList.getAdjustedDefault();
        if (adjustedDefault.size() > 0) {
            return adjustedDefault.get(0).toLanguageTag();
        }
        return null;
    }
}
