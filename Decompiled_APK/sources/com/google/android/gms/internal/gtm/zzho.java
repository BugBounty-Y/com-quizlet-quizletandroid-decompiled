package com.google.android.gms.internal.gtm;

import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import com.google.android.gms.tagmanager.impl.R$string;

/* loaded from: classes2.dex */
public final class zzho {
    private final Context zza;
    private final Context zzb;
    private final Intent zzc;
    private final zzix zzd;

    public zzho(Intent intent, Context context, Context context2, zzix zzixVar) {
        this.zza = context;
        this.zzb = context2;
        this.zzc = intent;
        this.zzd = zzixVar;
    }

    public final void zzb() throws Resources.NotFoundException {
        try {
            this.zzd.zzn(this.zzc.getData());
            String string = this.zzb.getResources().getString(R$string.tagmanager_preview_dialog_title);
            String string2 = this.zzb.getResources().getString(R$string.tagmanager_preview_dialog_message);
            String string3 = this.zzb.getResources().getString(R$string.tagmanager_preview_dialog_button);
            AlertDialog alertDialogCreate = new AlertDialog.Builder(this.zza).create();
            alertDialogCreate.setTitle(string);
            alertDialogCreate.setMessage(string2);
            alertDialogCreate.setButton(-1, string3, new zzhn(this));
            alertDialogCreate.show();
        } catch (Exception e) {
            zzhi.zza("Calling preview threw an exception: ".concat(String.valueOf(e.getMessage())));
        }
    }
}
