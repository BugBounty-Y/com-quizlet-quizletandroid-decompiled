package com.android.volley;

import android.os.SystemClock;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes.dex */
public final class x {
    public static final boolean c = y.a;
    public final ArrayList a = new ArrayList();
    public boolean b = false;

    public final synchronized void a(long j, String str) {
        if (this.b) {
            throw new IllegalStateException("Marker added to finished log");
        }
        this.a.add(new w(j, SystemClock.elapsedRealtime(), str));
    }

    public final synchronized void b(String str) {
        long j;
        this.b = true;
        ArrayList arrayList = this.a;
        if (arrayList.size() == 0) {
            j = 0;
        } else {
            j = ((w) arrayList.get(arrayList.size() - 1)).c - ((w) arrayList.get(0)).c;
        }
        if (j <= 0) {
            return;
        }
        long j2 = ((w) this.a.get(0)).c;
        y.a("(%-4d ms) %s", Long.valueOf(j), str);
        Iterator it2 = this.a.iterator();
        while (it2.hasNext()) {
            w wVar = (w) it2.next();
            long j3 = wVar.c;
            y.a("(+%-4d) [%2d] %s", Long.valueOf(j3 - j2), Long.valueOf(wVar.b), wVar.a);
            j2 = j3;
        }
    }

    public final void finalize() {
        if (this.b) {
            return;
        }
        b("Request on the loose");
        y.b("Marker log finalized without finish() - uncaught exit point for request", new Object[0]);
    }
}
