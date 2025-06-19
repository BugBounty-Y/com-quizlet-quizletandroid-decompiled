package com.snowplowanalytics.core.session;

import androidx.lifecycle.InterfaceC1250k;
import androidx.lifecycle.J;
import com.snowplowanalytics.core.tracker.e;
import java.util.HashMap;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class b implements InterfaceC1250k {
    public static final a a = new a();
    public static int b = 1;

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStart(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullExpressionValue("b", "TAG");
        e.a("b", "App enter foreground", new Object[0]);
        try {
            HashMap map = new HashMap();
            map.put("isForeground", Boolean.TRUE);
            com.snowplowanalytics.core.utils.c.b(map, "SnowplowLifecycleTracking");
        } catch (Exception e) {
            Intrinsics.checkNotNullExpressionValue("b", "TAG");
            e.b("b", "Method onEnterForeground raised an exception: %s", e);
        }
    }

    @Override // androidx.lifecycle.InterfaceC1250k
    public final void onStop(J owner) {
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullParameter(owner, "owner");
        Intrinsics.checkNotNullExpressionValue("b", "TAG");
        e.a("b", "App enter background", new Object[0]);
        try {
            HashMap map = new HashMap();
            map.put("isForeground", Boolean.FALSE);
            com.snowplowanalytics.core.utils.c.b(map, "SnowplowLifecycleTracking");
        } catch (Exception e) {
            Intrinsics.checkNotNullExpressionValue("b", "TAG");
            e.b("b", "Method onEnterBackground raised an exception: %s", e);
        }
    }
}
