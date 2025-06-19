package com.quizlet.uicommon.ui.states;

import android.content.Context;
import android.content.DialogInterface;
import com.quizlet.quizletandroid.R;
import com.quizlet.uicommon.ui.common.dialogs.QAlertDialogFragment;
import com.quizlet.uicommon.ui.common.dialogs.i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class b {
    public final i a(Context context, DialogInterface.OnClickListener onButtonClick, DialogInterface.OnCancelListener onCancel) {
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(onButtonClick, "onButtonClick");
        Intrinsics.checkNotNullParameter(onCancel, "onCancel");
        String message = context.getString(b());
        Intrinsics.checkNotNullExpressionValue(message, "getString(...)");
        Intrinsics.checkNotNullParameter(message, "message");
        String text = context.getString(R.string.OK);
        Intrinsics.checkNotNullExpressionValue(text, "getString(...)");
        Intrinsics.checkNotNullParameter(text, "text");
        return new i(new QAlertDialogFragment.DialogData(message, null, text, null, true, null), onButtonClick, null, onCancel);
    }

    public abstract int b();
}
