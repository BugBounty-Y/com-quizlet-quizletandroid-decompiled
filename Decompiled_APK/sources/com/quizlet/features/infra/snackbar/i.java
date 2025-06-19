package com.quizlet.features.infra.snackbar;

import android.content.res.Resources;
import android.view.View;
import com.google.android.gms.internal.mlkit_vision_barcode.I6;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i extends k {
    public i() {
        super("Offline", 6);
    }

    @Override // com.quizlet.features.infra.snackbar.k
    public final com.google.android.material.snackbar.h a(View view, String message, com.braze.ui.inappmessage.f clickListener) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(clickListener, "clickListener");
        com.google.android.material.snackbar.h hVarF = I6.f(view, message);
        Intrinsics.checkNotNullExpressionValue(hVarF, "getOfflineSnackbar(...)");
        return hVarF;
    }
}
