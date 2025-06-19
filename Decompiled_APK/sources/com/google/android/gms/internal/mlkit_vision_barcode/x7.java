package com.google.android.gms.internal.mlkit_vision_barcode;

import android.widget.RemoteViews;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class x7 {
    public static final /* synthetic */ int a = 0;

    public static final int a(RemoteViews remoteViews, androidx.glance.appwidget.N0 n0, int i, int i2, Integer num) {
        if (i == -1) {
            throw new IllegalArgumentException("viewStubId must not be View.NO_ID");
        }
        int iIntValue = num != null ? num.intValue() : n0.g.incrementAndGet();
        if (iIntValue != -1) {
            Intrinsics.checkNotNullParameter(remoteViews, "<this>");
            remoteViews.setInt(i, "setInflatedId", iIntValue);
        }
        if (i2 != 0) {
            Intrinsics.checkNotNullParameter(remoteViews, "<this>");
            remoteViews.setInt(i, "setLayoutResource", i2);
        }
        remoteViews.setViewVisibility(i, 0);
        return iIntValue;
    }

    public static void b(Throwable th) {
        if (th instanceof VirtualMachineError) {
            throw ((VirtualMachineError) th);
        }
        if (th instanceof ThreadDeath) {
            throw ((ThreadDeath) th);
        }
        if (th instanceof LinkageError) {
            throw ((LinkageError) th);
        }
    }
}
