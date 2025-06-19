package com.quizlet.features.infra.snackbar;

import android.content.res.Resources;
import android.view.View;
import com.quizlet.quizletandroid.R;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class d extends k {
    public d() {
        super("Dismiss", 2);
    }

    @Override // com.quizlet.features.infra.snackbar.k
    public final com.google.android.material.snackbar.h a(View view, String message, com.braze.ui.inappmessage.f clickListener) throws Resources.NotFoundException {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(message, "message");
        Intrinsics.checkNotNullParameter(clickListener, "clickListener");
        int iA = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.dismissSnackbarColor);
        b bVar = new b(view);
        bVar.b = message;
        bVar.g = R.dimen.snackbar_text_size;
        bVar.d = iA;
        bVar.e = com.quizlet.themes.extensions.a.a(view.getContext(), R.attr.textColorInverse);
        bVar.h = R.drawable.gray_ripple_unbounded;
        com.google.android.material.snackbar.h hVarA = bVar.a();
        Intrinsics.checkNotNullExpressionValue(hVarA, "getDismissSnackbar(...)");
        return hVarA;
    }
}
