package com.google.android.gms.common.wrappers;

import android.content.Context;

/* loaded from: classes2.dex */
public final class c {
    public static final c b;
    public b a;

    static {
        c cVar = new c();
        cVar.a = null;
        b = cVar;
    }

    public static b a(Context context) {
        b bVar;
        c cVar = b;
        synchronized (cVar) {
            try {
                if (cVar.a == null) {
                    if (context.getApplicationContext() != null) {
                        context = context.getApplicationContext();
                    }
                    cVar.a = new b(context);
                }
                bVar = cVar.a;
            } catch (Throwable th) {
                throw th;
            }
        }
        return bVar;
    }
}
