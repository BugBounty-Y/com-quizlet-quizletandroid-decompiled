package com.appsflyer.internal;

import android.content.Context;
import java.util.Map;
import kotlin.Metadata;
import org.jetbrains.annotations.NotNull;

@Metadata
/* loaded from: classes.dex */
public interface AFg1vSDK {

    @NotNull
    public static final AFa1ySDK AFa1ySDK = AFa1ySDK.AFAdRevenueData;

    public static final class AFa1ySDK {
        static final /* synthetic */ AFa1ySDK AFAdRevenueData = new AFa1ySDK();

        private AFa1ySDK() {
        }
    }

    @NotNull
    Map<String, String> AFAdRevenueData(@NotNull Context context);
}
