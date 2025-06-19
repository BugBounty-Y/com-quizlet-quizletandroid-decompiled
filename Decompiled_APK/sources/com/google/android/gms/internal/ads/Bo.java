package com.google.android.gms.internal.ads;

import android.os.Handler;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class Bo {
    public static final ArrayList b = new ArrayList(50);
    public final Handler a;

    public Bo(Handler handler) {
        this.a = handler;
    }

    public static /* bridge */ /* synthetic */ void d(C2367mo c2367mo) {
        ArrayList arrayList = b;
        synchronized (arrayList) {
            try {
                if (arrayList.size() < 50) {
                    arrayList.add(c2367mo);
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public static C2367mo e() {
        C2367mo c2367mo;
        ArrayList arrayList = b;
        synchronized (arrayList) {
            try {
                c2367mo = arrayList.isEmpty() ? new C2367mo() : (C2367mo) arrayList.remove(arrayList.size() - 1);
            } catch (Throwable th) {
                throw th;
            }
        }
        return c2367mo;
    }

    public final C2367mo a(int i, Object obj) {
        C2367mo c2367moE = e();
        c2367moE.a = this.a.obtainMessage(i, obj);
        return c2367moE;
    }

    public final boolean b(Runnable runnable) {
        return this.a.post(runnable);
    }

    public final boolean c(int i) {
        return this.a.sendEmptyMessage(i);
    }
}
