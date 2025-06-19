package com.braze.configuration;

import android.app.LocaleManager;
import android.os.SystemClock;
import java.time.Clock;

/* loaded from: classes.dex */
public abstract /* synthetic */ class g {
    public static /* bridge */ /* synthetic */ LocaleManager a(Object obj) {
        return (LocaleManager) obj;
    }

    public static /* bridge */ /* synthetic */ Class i() {
        return LocaleManager.class;
    }

    public static /* bridge */ /* synthetic */ Clock m() {
        return SystemClock.currentNetworkTimeClock();
    }
}
