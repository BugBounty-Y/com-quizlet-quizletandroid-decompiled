package com.quizlet.uicommon.ui.common.dialogs;

import android.content.DialogInterface;
import com.quizlet.uicommon.ui.common.dialogs.QAlertDialogFragment;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class i {
    public final QAlertDialogFragment.DialogData a;
    public final DialogInterface.OnClickListener b;
    public final com.quizlet.quizletandroid.ui.setcreation.fragments.b c;
    public final DialogInterface.OnCancelListener d;

    public i(QAlertDialogFragment.DialogData dialogData, DialogInterface.OnClickListener onClickListener, com.quizlet.quizletandroid.ui.setcreation.fragments.b bVar, DialogInterface.OnCancelListener onCancelListener) {
        Intrinsics.checkNotNullParameter(dialogData, "dialogData");
        this.a = dialogData;
        this.b = onClickListener;
        this.c = bVar;
        this.d = onCancelListener;
    }

    public final boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof i)) {
            return false;
        }
        i iVar = (i) obj;
        return this.a.equals(iVar.a) && Intrinsics.b(this.b, iVar.b) && Intrinsics.b(this.c, iVar.c) && Intrinsics.b(this.d, iVar.d);
    }

    public final int hashCode() {
        int iHashCode = this.a.hashCode() * 31;
        DialogInterface.OnClickListener onClickListener = this.b;
        int iHashCode2 = (iHashCode + (onClickListener == null ? 0 : onClickListener.hashCode())) * 31;
        com.quizlet.quizletandroid.ui.setcreation.fragments.b bVar = this.c;
        int iHashCode3 = (iHashCode2 + (bVar == null ? 0 : bVar.hashCode())) * 31;
        DialogInterface.OnCancelListener onCancelListener = this.d;
        return iHashCode3 + (onCancelListener != null ? onCancelListener.hashCode() : 0);
    }

    public final String toString() {
        return "Data(dialogData=" + this.a + ", positiveButtonOnClick=" + this.b + ", negativeButtonOnClick=" + this.c + ", onCancelListener=" + this.d + ")";
    }
}
