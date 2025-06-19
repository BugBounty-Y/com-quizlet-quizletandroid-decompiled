package com.quizlet.uicommon.ui.common.dialogs;

import android.os.Bundle;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class h {
    public static QAlertDialogFragment a(i data) {
        Intrinsics.checkNotNullParameter(data, "data");
        QAlertDialogFragment qAlertDialogFragment = new QAlertDialogFragment();
        Bundle bundle = new Bundle();
        bundle.putParcelable("textData", data.a);
        qAlertDialogFragment.setArguments(bundle);
        qAlertDialogFragment.q = data.b;
        qAlertDialogFragment.r = data.c;
        qAlertDialogFragment.s = data.d;
        return qAlertDialogFragment;
    }
}
