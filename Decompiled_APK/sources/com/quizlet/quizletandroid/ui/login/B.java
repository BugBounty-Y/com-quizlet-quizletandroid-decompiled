package com.quizlet.quizletandroid.ui.login;

import android.content.DialogInterface;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.EnumC5145a;

/* loaded from: classes3.dex */
public final /* synthetic */ class B implements DialogInterface.OnClickListener {
    public final /* synthetic */ int a;

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) {
        switch (this.a) {
            case 0:
                dialogInterface.dismiss();
                break;
            case 1:
                EnumC5145a enumC5145a = AztecText.q1;
                dialogInterface.dismiss();
                break;
            default:
                EnumC5145a enumC5145a2 = AztecText.q1;
                dialogInterface.dismiss();
                break;
        }
    }
}
