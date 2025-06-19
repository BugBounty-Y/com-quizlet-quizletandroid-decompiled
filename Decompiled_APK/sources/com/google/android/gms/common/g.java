package com.google.android.gms.common;

import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.res.Resources;
import android.os.Looper;
import android.os.Message;
import android.util.Log;
import com.google.android.gms.internal.ads.Ls;

/* loaded from: classes2.dex */
public final class g extends Ls {
    public final Context b;
    public final /* synthetic */ GoogleApiAvailability c;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public g(GoogleApiAvailability googleApiAvailability, Context context) {
        super(Looper.myLooper() == null ? Looper.getMainLooper() : Looper.myLooper(), 1);
        this.c = googleApiAvailability;
        this.b = context.getApplicationContext();
    }

    @Override // android.os.Handler
    public final void handleMessage(Message message) throws Resources.NotFoundException {
        int i = message.what;
        if (i != 1) {
            StringBuilder sb = new StringBuilder(String.valueOf(i).length() + 39);
            sb.append("Don't know how to handle this message: ");
            sb.append(i);
            Log.w("GoogleApiAvailability", sb.toString());
            return;
        }
        int i2 = c.a;
        GoogleApiAvailability googleApiAvailability = this.c;
        Context context = this.b;
        int iC = googleApiAvailability.c(context, i2);
        int i3 = d.e;
        if (iC == 1 || iC == 2 || iC == 3 || iC == 9) {
            Intent intentB = googleApiAvailability.b(context, "n", iC);
            googleApiAvailability.g(context, iC, intentB == null ? null : PendingIntent.getActivity(context, 0, intentB, 201326592));
        }
    }
}
