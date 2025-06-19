package com.google.android.gms.internal.ads;

import android.content.Context;
import android.media.Spatializer;
import android.os.Build;
import android.os.Handler;
import android.text.TextUtils;
import android.util.Pair;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.RandomAccess;

/* loaded from: classes2.dex */
public final class VF {
    public static final C1853au i = new C1853au(new B2(6));
    public C2436oD a;
    public C2050fG b;
    public final Object c;
    public final Context d;
    public PF e;
    public androidx.browser.customtabs.k f;
    public Wl g;
    public final TD h;

    public VF(Context context) {
        TD td = new TD(19);
        PF pf = PF.C;
        this.c = new Object();
        this.d = context != null ? context.getApplicationContext() : null;
        this.h = td;
        if (pf != null) {
            this.e = pf;
        } else {
            OF of = new OF(pf);
            of.a(pf);
            this.e = new PF(of);
        }
        this.g = Wl.b;
        if (this.e.x && context == null) {
            AbstractC2096gb.J("DefaultTrackSelector", "Audio channel count constraints cannot be applied without reference to Context. Build the track selector instance with one of the non-deprecated constructors that take a Context argument.");
        }
    }

    public static int a(C1832aG c1832aG, String str, boolean z) {
        if (!TextUtils.isEmpty(str) && str.equals(c1832aG.d)) {
            return 4;
        }
        String strB = b(str);
        String strB2 = b(c1832aG.d);
        if (strB2 == null || strB == null) {
            return (z && strB2 == null) ? 1 : 0;
        }
        if (strB2.startsWith(strB) || strB.startsWith(strB2)) {
            return 3;
        }
        String str2 = Yo.a;
        return strB2.split("-", 2)[0].equals(strB.split("-", 2)[0]) ? 2 : 0;
    }

    public static String b(String str) {
        if (TextUtils.isEmpty(str) || TextUtils.equals(str, "und")) {
            return null;
        }
        return str;
    }

    public static final Pair f(int i2, com.quizlet.data.repository.folderwithcreatorinclass.e eVar, int[][][] iArr, SF sf, Comparator comparator) {
        RandomAccess randomAccessS;
        com.quizlet.data.repository.folderwithcreatorinclass.e eVar2 = eVar;
        ArrayList arrayList = new ArrayList();
        int i3 = 0;
        while (i3 < 2) {
            if (i2 == ((int[]) eVar2.a)[i3]) {
                HF hf = ((HF[]) eVar2.b)[i3];
                for (int i4 = 0; i4 < hf.a; i4++) {
                    J9 j9A = hf.a(i4);
                    Bu buA = sf.a(i3, j9A, iArr[i3][i4]);
                    int i5 = j9A.a;
                    boolean[] zArr = new boolean[i5];
                    int i6 = 0;
                    while (i6 < i5) {
                        int i7 = i6 + 1;
                        TF tf = (TF) buA.get(i6);
                        int iA = tf.a();
                        if (!zArr[i6] && iA != 0) {
                            if (iA == 1) {
                                randomAccessS = AbstractC2330lu.s(tf);
                            } else {
                                ArrayList arrayList2 = new ArrayList();
                                arrayList2.add(tf);
                                for (int i8 = i7; i8 < i5; i8++) {
                                    TF tf2 = (TF) buA.get(i8);
                                    if (tf2.a() == 2 && tf.b(tf2)) {
                                        arrayList2.add(tf2);
                                        zArr[i8] = true;
                                    }
                                }
                                randomAccessS = arrayList2;
                            }
                            arrayList.add(randomAccessS);
                        }
                        i6 = i7;
                    }
                }
            }
            i3++;
            eVar2 = eVar;
        }
        if (arrayList.isEmpty()) {
            return null;
        }
        List list = (List) Collections.max(arrayList, comparator);
        int[] iArr2 = new int[list.size()];
        for (int i9 = 0; i9 < list.size(); i9++) {
            iArr2[i9] = ((TF) list.get(i9)).c;
        }
        TF tf3 = (TF) list.get(0);
        return Pair.create(new WF(tf3.b, iArr2), Integer.valueOf(tf3.a));
    }

    public final void c() {
        androidx.browser.customtabs.k kVar;
        Spatializer spatializer;
        QF qf;
        Handler handler;
        if (Build.VERSION.SDK_INT >= 32 && (kVar = this.f) != null && (spatializer = (Spatializer) kVar.b) != null && (qf = (QF) kVar.d) != null && (handler = (Handler) kVar.c) != null) {
            spatializer.removeOnSpatializerStateChangedListener(qf);
            handler.removeCallbacksAndMessages(null);
        }
        this.a = null;
        this.b = null;
    }

    public final void d(Wl wl) {
        if (this.g.equals(wl)) {
            return;
        }
        this.g = wl;
        e();
    }

    public final void e() {
        boolean z;
        C2436oD c2436oD;
        androidx.browser.customtabs.k kVar;
        synchronized (this.c) {
            try {
                z = false;
                if (this.e.x && Build.VERSION.SDK_INT >= 32 && (kVar = this.f) != null && kVar.a) {
                    z = true;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
        if (!z || (c2436oD = this.a) == null) {
            return;
        }
        c2436oD.h.c(10);
    }
}
