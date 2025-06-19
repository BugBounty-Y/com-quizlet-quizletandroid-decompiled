package com.google.android.gms.common;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.os.Bundle;
import androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t;
import com.google.android.gms.common.internal.u;

/* loaded from: classes2.dex */
public class f extends DialogInterfaceOnCancelListenerC1151t {
    public AlertDialog q;
    public DialogInterface.OnCancelListener r;
    public AlertDialog s;

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t
    public final Dialog K(Bundle bundle) {
        AlertDialog alertDialog = this.q;
        if (alertDialog != null) {
            return alertDialog;
        }
        this.h = false;
        if (this.s == null) {
            Context context = getContext();
            u.h(context);
            this.s = new AlertDialog.Builder(context).create();
        }
        return this.s;
    }

    @Override // androidx.fragment.app.DialogInterfaceOnCancelListenerC1151t, android.content.DialogInterface.OnCancelListener
    public final void onCancel(DialogInterface dialogInterface) {
        DialogInterface.OnCancelListener onCancelListener = this.r;
        if (onCancelListener != null) {
            onCancelListener.onCancel(dialogInterface);
        }
    }
}
