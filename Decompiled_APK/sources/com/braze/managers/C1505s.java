package com.braze.managers;

import android.content.Context;
import com.braze.support.BrazeImageUtils;
import com.braze.support.BrazeLogger;
import kotlin.Pair;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.braze.managers.s, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1505s {
    public final String a(Context context, boolean z) {
        Intrinsics.checkNotNullParameter(context, "context");
        try {
            Pair<Integer, Integer> displayHeightAndWidthPixels = BrazeImageUtils.getDisplayHeightAndWidthPixels(context);
            int iIntValue = ((Number) displayHeightAndWidthPixels.a).intValue();
            int iIntValue2 = ((Number) displayHeightAndWidthPixels.b).intValue();
            if (z) {
                StringBuilder sb = new StringBuilder();
                sb.append(iIntValue);
                sb.append('x');
                sb.append(iIntValue2);
                return sb.toString();
            }
            StringBuilder sb2 = new StringBuilder();
            sb2.append(iIntValue2);
            sb2.append('x');
            sb2.append(iIntValue);
            return sb2.toString();
        } catch (Exception e) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.E, (Throwable) e, false, (Function0) new P(4), 4, (Object) null);
            return null;
        }
    }

    public static final String a() {
        return "Failed to obtain device resolution";
    }
}
