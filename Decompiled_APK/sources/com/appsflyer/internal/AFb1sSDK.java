package com.appsflyer.internal;

import android.graphics.Color;
import android.text.TextUtils;
import android.view.ViewConfiguration;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.util.Map;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public final class AFb1sSDK {

    @NotNull
    private final AFh1rSDK getRevenue;

    public AFb1sSDK(@NotNull AFh1rSDK aFh1rSDK) {
        Intrinsics.checkNotNullParameter(aFh1rSDK, "");
        this.getRevenue = aFh1rSDK;
    }

    public final void afInfoLog() throws Throwable {
        try {
            Map map = AFa1kSDK.i;
            Object declaredConstructor = map.get(-496653013);
            if (declaredConstructor == null) {
                declaredConstructor = ((Class) AFa1kSDK.getCurrencyIso4217Code(87 - (ViewConfiguration.getScrollDefaultDelay() >> 16), (char) (28154 - TextUtils.indexOf((CharSequence) "", '0', 0, 0)), 36 - Color.argb(0, 0, 0, 0))).getDeclaredConstructor(null);
                map.put(-496653013, declaredConstructor);
            }
            Object objNewInstance = ((Constructor) declaredConstructor).newInstance(null);
            Object[] objArr = {this.getRevenue};
            Object method = map.get(-1581670163);
            if (method == null) {
                method = ((Class) AFa1kSDK.getCurrencyIso4217Code(87 - TextUtils.indexOf("", "", 0, 0), (char) (28155 - (ViewConfiguration.getKeyRepeatDelay() >> 16)), 36 - (ViewConfiguration.getScrollBarSize() >> 8))).getMethod("getRevenue", AFh1rSDK.class);
                map.put(-1581670163, method);
            }
            ((Method) method).invoke(objNewInstance, objArr);
        } catch (Throwable th) {
            Throwable cause = th.getCause();
            if (cause == null) {
                throw th;
            }
            throw cause;
        }
    }
}
