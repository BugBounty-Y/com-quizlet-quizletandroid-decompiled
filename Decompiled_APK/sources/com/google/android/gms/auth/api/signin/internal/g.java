package com.google.android.gms.auth.api.signin.internal;

import android.content.Context;
import androidx.appcompat.widget.C0122z;
import com.google.android.gms.common.api.internal.C1647e;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes2.dex */
public abstract class g {
    public static final C0122z a = new C0122z("GoogleSignInCommon", new String[0]);

    public static void a(Context context) {
        h.B(context).C();
        Set set = com.google.android.gms.common.api.h.a;
        synchronized (set) {
        }
        Iterator it2 = set.iterator();
        if (it2.hasNext()) {
            ((com.google.android.gms.common.api.h) it2.next()).getClass();
            throw new UnsupportedOperationException();
        }
        C1647e.a();
    }
}
