package com.pubmatic.sdk.common.utility;

import android.R;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;

/* loaded from: classes2.dex */
public class c {

    public class a implements DialogInterface.OnCancelListener {
        final /* synthetic */ com.pubmatic.sdk.common.utility.b a;

        public a(com.pubmatic.sdk.common.utility.b bVar) {
            this.a = bVar;
        }

        @Override // android.content.DialogInterface.OnCancelListener
        public void onCancel(DialogInterface dialogInterface) {
            this.a.onCancel(dialogInterface, 0);
        }
    }

    public class b implements DialogInterface.OnClickListener {
        final /* synthetic */ com.pubmatic.sdk.common.utility.b a;

        public b(com.pubmatic.sdk.common.utility.b bVar) {
            this.a = bVar;
        }

        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i) {
            this.a.onCancel(dialogInterface, i);
        }
    }

    /* renamed from: com.pubmatic.sdk.common.utility.c$c, reason: collision with other inner class name */
    public class DialogInterfaceOnClickListenerC0014c implements DialogInterface.OnClickListener {
        final /* synthetic */ com.pubmatic.sdk.common.utility.b a;

        public DialogInterfaceOnClickListenerC0014c(com.pubmatic.sdk.common.utility.b bVar) {
            this.a = bVar;
        }

        @Override // android.content.DialogInterface.OnClickListener
        public void onClick(DialogInterface dialogInterface, int i) {
            this.a.onSuccess(dialogInterface, i);
        }
    }

    public static AlertDialog.Builder build(Context context, String str, String str2, com.pubmatic.sdk.common.utility.b bVar) {
        boolean z;
        try {
            z = !((Activity) context).isFinishing();
        } catch (Exception unused) {
            z = true;
        }
        if (context == null || !z) {
            return null;
        }
        AlertDialog.Builder builder = new AlertDialog.Builder(context, R.style.Theme.Material.Dialog.Alert);
        builder.setTitle(str).setMessage(str2).setCancelable(true).setPositiveButton("YES", new DialogInterfaceOnClickListenerC0014c(bVar)).setNegativeButton("NO", new b(bVar)).setOnCancelListener(new a(bVar)).create();
        return builder;
    }
}
