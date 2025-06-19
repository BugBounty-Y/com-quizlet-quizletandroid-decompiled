package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.content.Context;
import android.content.Intent;
import com.quizlet.data.model.AbstractC4178x;
import com.quizlet.quizletandroid.ui.globalnav.GlobalNavigationActivity;
import com.quizlet.quizletandroid.ui.globalnav.data.GlobalNavReroute;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public abstract class D4 {
    public static long a;

    public static final Intent a(Context context, GlobalNavReroute globalNavReroute) {
        Intrinsics.checkNotNullParameter(context, "context");
        String str = GlobalNavigationActivity.u;
        Intent intentB = AbstractC4178x.b(context, "context", context, GlobalNavigationActivity.class);
        if (globalNavReroute != null) {
            intentB.putExtra("GlobalNav.navReroute", globalNavReroute);
        }
        return intentB;
    }
}
