package com.google.android.gms.common.internal;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Build;
import android.util.Log;
import androidx.annotation.NonNull;
import com.google.android.gms.common.api.internal.InterfaceC1649g;

/* loaded from: classes2.dex */
public abstract class o implements DialogInterface.OnClickListener {
    public static o b(Activity activity, Intent intent, int i) {
        return new m(activity, intent, i);
    }

    public static o c(@NonNull InterfaceC1649g interfaceC1649g, Intent intent, int i) {
        return new n(intent, interfaceC1649g);
    }

    public abstract void a();

    @Override // android.content.DialogInterface.OnClickListener
    public final void onClick(DialogInterface dialogInterface, int i) {
        try {
            try {
                a();
            } catch (ActivityNotFoundException e) {
                Log.e("DialogRedirect", true == Build.FINGERPRINT.contains("generic") ? "Failed to start resolution intent. This may occur when resolving Google Play services connection issues on emulators with Google APIs but not Google Play Store." : "Failed to start resolution intent.", e);
            }
        } finally {
            dialogInterface.dismiss();
        }
    }
}
