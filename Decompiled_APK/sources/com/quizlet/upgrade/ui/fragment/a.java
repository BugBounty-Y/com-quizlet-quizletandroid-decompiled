package com.quizlet.upgrade.ui.fragment;

import android.app.Dialog;
import android.os.Bundle;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.e;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata
/* loaded from: classes3.dex */
public final class a extends DialogInterfaceOnCancelListenerC1151t {
    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        com.quizlet.infra.legacysyncengine.tasks.parse.b bVar = new com.quizlet.infra.legacysyncengine.tasks.parse.b(this, 26);
        e.a aVar = new e.a(getActivity());
        aVar.b = false;
        aVar.f(R.string.upgrade_v2_error_dialog_title);
        aVar.c(R.string.upgrade_v2_error_dialog_message);
        aVar.e(R.string.upgrade_v2_error_dialog_button_label, bVar);
        com.quizlet.uicommon.ui.common.dialogs.e eVarB = aVar.b();
        Intrinsics.checkNotNullExpressionValue(eVarB, "create(...)");
        return eVarB;
    }
}
