package com.google.android.gms.auth.api.signin;

import android.content.Context;
import androidx.appcompat.widget.C0122z;
import com.google.android.gms.auth.api.signin.internal.b;
import com.google.android.gms.auth.api.signin.internal.f;
import com.google.android.gms.auth.api.signin.internal.g;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.e;
import com.google.android.gms.common.api.internal.BasePendingResult;
import com.google.android.gms.common.api.internal.F;
import com.google.android.gms.common.api.internal.p;
import com.google.android.gms.common.api.l;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.dynamite.c;
import com.onetrust.otpublishers.headless.Internal.Helper.h;

/* loaded from: classes2.dex */
public final class a extends e {
    public static int l = 1;

    public final void d() {
        BasePendingResult lVar;
        boolean z = e() == 3;
        C0122z c0122z = g.a;
        if (c0122z.b <= 3) {
            ((String) c0122z.d).concat("Revoking access");
        }
        Context context = this.a;
        String strE = com.google.android.gms.auth.api.signin.internal.a.a(context).e("refreshToken");
        g.a(context);
        if (!z) {
            p pVar = this.i;
            f fVar = new f(pVar, 1);
            pVar.a(fVar);
            lVar = fVar;
        } else if (strE == null) {
            C0122z c0122z2 = b.c;
            Status status = new Status(4, null, null, null);
            u.a("Status code must not be SUCCESS", true ^ status.a());
            lVar = new l(status);
            lVar.setResult(status);
        } else {
            b bVar = new b(strE);
            new Thread(bVar).start();
            lVar = bVar.b;
        }
        lVar.addStatusListener(new F(lVar, new com.google.android.gms.tasks.f(), new h(9)));
    }

    public final synchronized int e() {
        int i;
        try {
            i = l;
            if (i == 1) {
                Context context = this.a;
                GoogleApiAvailability googleApiAvailability = GoogleApiAvailability.d;
                int iC = googleApiAvailability.c(context, 12451000);
                if (iC == 0) {
                    i = 4;
                    l = 4;
                } else if (googleApiAvailability.b(context, null, iC) != null || c.a(context, "com.google.android.gms.auth.api.fallback") == 0) {
                    i = 2;
                    l = 2;
                } else {
                    i = 3;
                    l = 3;
                }
            }
        } catch (Throwable th) {
            throw th;
        }
        return i;
    }
}
