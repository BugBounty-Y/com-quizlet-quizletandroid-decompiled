package com.quizlet.features.infra.snackbar;

import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class c extends k {
    public c() {
        super("Dark", 1);
    }

    @Override // com.quizlet.features.infra.snackbar.k
    public final com.google.android.material.snackbar.h a(View view, String message, com.braze.ui.inappmessage.f clickListener) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(clickListener, "clickListener");
        com.google.android.material.snackbar.h hVarD = I6.d(view, message);
        Intrinsics.checkNotNullExpressionValue(hVarD, "getDarkSnackbar(...)");
        return hVarD;
    }
}
