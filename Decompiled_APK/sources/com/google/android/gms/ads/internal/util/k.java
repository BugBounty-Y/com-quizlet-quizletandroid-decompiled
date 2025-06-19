package com.google.android.gms.ads.internal.util;

import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;

/* loaded from: classes2.dex */
public final class k implements Runnable {
    public final /* synthetic */ Context a;
    public final /* synthetic */ String b;
    public final /* synthetic */ boolean c;
    public final /* synthetic */ boolean d;

    public k(Context context, String str, boolean z, boolean z2) {
        this.a = context;
        this.b = str;
        this.c = z;
        this.d = z2;
    }

    @Override // java.lang.Runnable
    public final void run() {
        F f = com.google.android.gms.ads.internal.j.C.c;
        Context context = this.a;
        AlertDialog.Builder builderJ = F.j(context);
        builderJ.setMessage(this.b);
        if (this.c) {
            builderJ.setTitle("Error");
        } else {
            builderJ.setTitle("Info");
        }
        if (this.d) {
            builderJ.setNeutralButton("Dismiss", (DialogInterface.OnClickListener) null);
        } else {
            builderJ.setPositiveButton("Learn More", new DialogInterfaceOnClickListenerC1630f(context, 2));
            builderJ.setNegativeButton("Dismiss", (DialogInterface.OnClickListener) null);
        }
        builderJ.create().show();
    }
}
