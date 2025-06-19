package com.google.android.gms.measurement.internal;

import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.util.Log;
import java.io.IOException;
import java.util.Map;

/* loaded from: classes2.dex */
public final class G implements Runnable {
    public final /* synthetic */ int a = 0;
    public final int b;
    public final String c;
    public final Object d;
    public final Object e;
    public final Object f;
    public final Object g;

    public G(I i, int i2, String str, Object obj, Object obj2, Object obj3) {
        this.b = i2;
        this.c = str;
        this.d = obj;
        this.e = obj2;
        this.f = obj3;
        this.g = i;
    }

    @Override // java.lang.Runnable
    public final void run() {
        switch (this.a) {
            case 0:
                I i = (I) this.g;
                O o = ((Y) i.b).h;
                Y.h(o);
                if (!o.c) {
                    Log.println(6, i.d0(), "Persisted config not initialized. Not logging error/warn");
                    return;
                }
                if (i.d == 0) {
                    C3864e c3864e = ((Y) i.b).g;
                    if (c3864e.f == null) {
                        synchronized (c3864e) {
                            try {
                                if (c3864e.f == null) {
                                    Y y = (Y) c3864e.b;
                                    ApplicationInfo applicationInfo = y.a.getApplicationInfo();
                                    String strH = com.google.android.gms.common.util.c.h();
                                    if (applicationInfo != null) {
                                        String str = applicationInfo.processName;
                                        c3864e.f = Boolean.valueOf(str != null && str.equals(strH));
                                    }
                                    if (c3864e.f == null) {
                                        c3864e.f = Boolean.TRUE;
                                        I i2 = y.i;
                                        Y.k(i2);
                                        i2.g.f("My process not in the list of running processes");
                                    }
                                }
                            } finally {
                            }
                        }
                    }
                    if (c3864e.f.booleanValue()) {
                        i.d = 'C';
                    } else {
                        i.d = 'c';
                    }
                }
                if (i.e < 0) {
                    ((Y) i.b).g.Z();
                    i.e = 119002L;
                }
                char cCharAt = "01VDIWEA?".charAt(this.b);
                char c = i.d;
                long j = i.e;
                String str2 = this.c;
                String strB0 = I.b0(true, str2, this.d, this.e, this.f);
                StringBuilder sb = new StringBuilder("2");
                sb.append(cCharAt);
                sb.append(c);
                sb.append(j);
                String strT = android.support.v4.media.session.a.t(sb, ":", strB0);
                if (strT.length() > 1024) {
                    strT = str2.substring(0, 1024);
                }
                androidx.work.impl.background.greedy.d dVar = o.g;
                if (dVar != null) {
                    O o2 = (O) dVar.e;
                    o2.S();
                    if (((O) dVar.e).X().getLong((String) dVar.b, 0L) == 0) {
                        dVar.l();
                    }
                    if (strT == null) {
                        strT = "";
                    }
                    SharedPreferences sharedPreferencesX = o2.X();
                    String str3 = (String) dVar.c;
                    long j2 = sharedPreferencesX.getLong(str3, 0L);
                    String str4 = (String) dVar.d;
                    if (j2 <= 0) {
                        SharedPreferences.Editor editorEdit = o2.X().edit();
                        editorEdit.putString(str4, strT);
                        editorEdit.putLong(str3, 1L);
                        editorEdit.apply();
                        return;
                    }
                    x1 x1Var = ((Y) o2.b).l;
                    Y.h(x1Var);
                    long jNextLong = x1Var.d0().nextLong() & Long.MAX_VALUE;
                    long j3 = j2 + 1;
                    long j4 = Long.MAX_VALUE / j3;
                    SharedPreferences.Editor editorEdit2 = o2.X().edit();
                    if (jNextLong < j4) {
                        editorEdit2.putString(str4, strT);
                    }
                    editorEdit2.putLong(str3, j3);
                    editorEdit2.apply();
                    return;
                }
                return;
            default:
                ((K) this.d).a(this.c, this.b, (IOException) this.e, (byte[]) this.f, (Map) this.g);
                return;
        }
    }

    public /* synthetic */ G(String str, K k, int i, IOException iOException, byte[] bArr, Map map) {
        com.google.android.gms.common.internal.u.h(k);
        this.d = k;
        this.b = i;
        this.e = iOException;
        this.f = bArr;
        this.c = str;
        this.g = map;
    }
}
