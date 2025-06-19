package com.braze.dispatch;

import android.content.Context;
import com.braze.configuration.BrazeConfigurationProvider;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class a extends BrazeConfigurationProvider {
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public a(Context context) {
        super(context);
        Intrinsics.checkNotNullParameter(context, "context");
    }
}
