package com.quizlet.upgrade.ui.fragment;

import android.content.DialogInterface;
import android.os.Bundle;
import androidx.compose.runtime.C0814p;
import androidx.compose.runtime.InterfaceC0806l;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3178j5;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class FreeTrialConfirmationFragment extends Hilt_FreeTrialConfirmationFragment {
    @Override // com.quizlet.baseui.base.BaseComposeBottomSheetFragment
    public final void S(InterfaceC0806l interfaceC0806l, int i) {
        C0814p c0814p = (C0814p) interfaceC0806l;
        c0814p.X(1383941816);
        AbstractC3178j5.c(null, false, null, androidx.compose.runtime.internal.e.e(-1654918362, new com.quizlet.quizletandroid.ui.studymodes.assistant.checkpoint.c(this, 9), c0814p), c0814p, 3072, 7);
        c0814p.p(false);
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnDismissListener
    public final void onDismiss(DialogInterface dialog) {
        Intrinsics.checkNotNullParameter(dialog, "dialog");
        getParentFragmentManager().g0(new Bundle(0), "freeTrialConfirmationRequest");
        super.onDismiss(dialog);
    }
}
