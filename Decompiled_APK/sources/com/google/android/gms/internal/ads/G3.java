package com.google.android.gms.internal.ads;

import android.os.SystemClock;
import java.util.ArrayList;
import java.util.Iterator;

/* loaded from: classes2.dex */
public final class G3 {
    public static final boolean c = H3.a;
    public final ArrayList a = new ArrayList();
    public boolean b = false;

    public final synchronized void a(long j, String str) {
        if (this.b) {
            throw new IllegalStateException("Marker added to finished log");
        }
        this.a.add(new F3(j, SystemClock.elapsedRealtime(), str));
    }

    public final synchronized void b(String str) {
        long j;
        this.b = true;
        ArrayList arrayList = this.a;
        if (arrayList.size() == 0) {
            j = 0;
        } else {
            j = ((F3) arrayList.get(arrayList.size() - 1)).c - ((F3) arrayList.get(0)).c;
        }
        if (j > 0) {
            long j2 = ((F3) arrayList.get(0)).c;
            H3.c("(%-4d ms) %s", Long.valueOf(j), str);
            Iterator it2 = arrayList.iterator();
            while (it2.hasNext()) {
                F3 f3 = (F3) it2.next();
                long j3 = f3.c;
                H3.c("(+%-4d) [%2d] %s", Long.valueOf(j3 - j2), Long.valueOf(f3.b), f3.a);
                j2 = j3;
            }
        }
    }

    public final void finalize() {
        if (this.b) {
            return;
        }
        b("Request on the loose");
        H3.a("Marker log finalized without finish() - uncaught exit point for request", new Object[0]);
    }
}
