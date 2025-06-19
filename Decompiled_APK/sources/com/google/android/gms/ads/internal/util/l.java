package com.google.android.gms.ads.internal.util;

import android.content.Context;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.internal.ads.A3;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import com.google.android.gms.internal.ads.B3;
import com.google.android.gms.internal.ads.C1;
import com.google.android.gms.internal.ads.C1732Mb;
import com.google.android.gms.internal.ads.C3;
import com.google.android.gms.internal.ads.F9;
import java.io.File;
import java.util.regex.Pattern;

/* loaded from: classes2.dex */
public final class l extends C1732Mb {
    public final Context e;

    public l(Context context, C1 c1) {
        super(c1);
        this.e = context;
    }

    public static C3 m(Context context) {
        C3 c3 = new C3(new com.android.volley.toolbox.d(new File(new File(context.getCacheDir(), "admob_volley").getPath()), 1), new l(context, new C1(23)));
        c3.g();
        return c3;
    }

    @Override // com.google.android.gms.internal.ads.C1732Mb, com.google.android.gms.internal.ads.InterfaceC2855y3
    public final A3 f(B3 b3) {
        if (b3.b == 0) {
            String str = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.y4);
            String str2 = b3.c;
            if (Pattern.matches(str, str2)) {
                com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
                com.google.android.gms.common.c cVar2 = com.google.android.gms.common.c.b;
                Context context = this.e;
                if (cVar2.c(context, 13400000) == 0) {
                    A3 a3F = new F9(context).f(b3);
                    if (a3F != null) {
                        A.l("Got gmscore asset response: ".concat(String.valueOf(str2)));
                        return a3F;
                    }
                    A.l("Failed to get gmscore asset response: ".concat(String.valueOf(str2)));
                }
            }
        }
        return super.f(b3);
    }
}
