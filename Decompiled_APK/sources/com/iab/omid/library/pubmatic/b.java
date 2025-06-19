package com.iab.omid.library.pubmatic;

import android.content.Context;
import com.iab.omid.library.pubmatic.internal.i;
import com.iab.omid.library.pubmatic.utils.e;
import com.iab.omid.library.pubmatic.utils.g;

/* loaded from: classes2.dex */
public class b {
    private boolean a;

    private void b(Context context) {
        g.a(context, "Application Context cannot be null");
    }

    public String a() {
        return "1.4.11-Pubmatic";
    }

    public void c() {
        g.a();
        com.iab.omid.library.pubmatic.internal.a.a().d();
    }

    public void a(Context context) {
        b(context);
        if (b()) {
            return;
        }
        a(true);
        i.c().a(context);
        com.iab.omid.library.pubmatic.internal.b.g().a(context);
        com.iab.omid.library.pubmatic.utils.a.a(context);
        com.iab.omid.library.pubmatic.utils.c.a(context);
        e.a(context);
        com.iab.omid.library.pubmatic.internal.g.b().a(context);
        com.iab.omid.library.pubmatic.internal.a.a().a(context);
    }

    public boolean b() {
        return this.a;
    }

    public void a(boolean z) {
        this.a = z;
    }
}
