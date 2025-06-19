package com.quizlet.quizletandroid.ui.startpage.nav2.adapters;

import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3299x6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a extends com.quizlet.baserecyclerview.b {
    public static void h(View view) {
        Intrinsics.checkNotNullParameter(view, "view");
        if (AbstractC3299x6.a(view, true)) {
            view.requestLayout();
        }
    }
}
