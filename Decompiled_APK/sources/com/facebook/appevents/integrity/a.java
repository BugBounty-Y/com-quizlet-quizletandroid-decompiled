package com.facebook.appevents.integrity;

import android.os.Bundle;
import java.util.HashSet;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class a {
    public static boolean b;
    public static final a a = new a();
    public static HashSet c = new HashSet();

    public static final void a(Bundle bundle) {
        if (com.facebook.internal.instrument.crashshield.a.b(a.class)) {
            return;
        }
        try {
            if (b && bundle != null) {
                Iterator it2 = c.iterator();
                while (it2.hasNext()) {
                    bundle.remove((String) it2.next());
                }
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(a.class, th);
        }
    }
}
