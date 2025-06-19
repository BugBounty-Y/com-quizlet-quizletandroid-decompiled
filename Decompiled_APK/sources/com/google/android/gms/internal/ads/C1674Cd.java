package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.text.TextUtils;
import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.util.client.VersionInfoParcel;
import com.google.android.gms.internal.mlkit_vision_common.U2;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: com.google.android.gms.internal.ads.Cd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1674Cd {
    public static final boolean r;
    public final Context a;
    public final String b;
    public final VersionInfoParcel c;
    public final C2902z7 d;
    public final B7 e;
    public final androidx.camera.camera2.internal.concurrent.a f;
    public final long[] g;
    public final String[] h;
    public boolean i;
    public boolean j;
    public boolean k;
    public boolean l;
    public boolean m;
    public AbstractC2656td n;
    public boolean o;
    public boolean p;
    public long q;

    static {
        r = C1614q.f.e.nextInt(100) < ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Gc)).intValue();
    }

    public C1674Cd(Context context, VersionInfoParcel versionInfoParcel, String str, B7 b7, C2902z7 c2902z7) {
        com.quizlet.data.repository.user.a aVar = new com.quizlet.data.repository.user.a(5);
        aVar.y("min_1", Double.MIN_VALUE, 1.0d);
        aVar.y("1_5", 1.0d, 5.0d);
        aVar.y("5_10", 5.0d, 10.0d);
        aVar.y("10_20", 10.0d, 20.0d);
        aVar.y("20_30", 20.0d, 30.0d);
        aVar.y("30_max", 30.0d, Double.MAX_VALUE);
        this.f = new androidx.camera.camera2.internal.concurrent.a(aVar);
        this.i = false;
        this.j = false;
        this.k = false;
        this.l = false;
        this.q = -1L;
        this.a = context;
        this.c = versionInfoParcel;
        this.b = str;
        this.e = b7;
        this.d = c2902z7;
        String str2 = (String) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.H);
        if (str2 == null) {
            this.h = new String[0];
            this.g = new long[0];
            return;
        }
        String[] strArrSplit = TextUtils.split(str2, ",");
        int length = strArrSplit.length;
        this.h = new String[length];
        this.g = new long[length];
        for (int i = 0; i < strArrSplit.length; i++) {
            try {
                this.g[i] = Long.parseLong(strArrSplit[i]);
            } catch (NumberFormatException e) {
                com.google.android.gms.ads.internal.util.client.i.i("Unable to parse frame hash target time number.", e);
                this.g[i] = -1;
            }
        }
    }

    public final void a(AbstractC2656td abstractC2656td) {
        B7 b7 = this.e;
        AbstractC2096gb.h(b7, this.d, "vpc2");
        this.i = true;
        b7.b("vpn", abstractC2656td.s());
        this.n = abstractC2656td;
    }

    public final void b() {
        this.m = true;
        if (!this.j || this.k) {
            return;
        }
        AbstractC2096gb.h(this.e, this.d, "vfp2");
        this.k = true;
    }

    public final void c() {
        Bundle bundleD;
        if (!r || this.o) {
            return;
        }
        Bundle bundle = new Bundle();
        bundle.putString(DBUserFields.Names.USER_UPGRADE_TYPE, "native-player-metrics");
        bundle.putString("request", this.b);
        bundle.putString("player", this.n.s());
        androidx.camera.camera2.internal.concurrent.a aVar = this.f;
        aVar.getClass();
        String[] strArr = (String[]) aVar.c;
        ArrayList arrayList = new ArrayList(strArr.length);
        for (int i = 0; i < strArr.length; i++) {
            String str = strArr[i];
            double d = ((double[]) aVar.e)[i];
            double d2 = ((double[]) aVar.d)[i];
            int i2 = ((int[]) aVar.f)[i];
            arrayList.add(new com.google.android.gms.ads.internal.util.m(str, d, d2, i2 / aVar.b, i2));
        }
        Iterator it2 = arrayList.iterator();
        while (it2.hasNext()) {
            com.google.android.gms.ads.internal.util.m mVar = (com.google.android.gms.ads.internal.util.m) it2.next();
            String str2 = mVar.a;
            bundle.putString("fps_c_".concat(String.valueOf(str2)), Integer.toString(mVar.e));
            bundle.putString("fps_p_".concat(String.valueOf(str2)), Double.toString(mVar.d));
        }
        int i3 = 0;
        while (true) {
            long[] jArr = this.g;
            if (i3 >= jArr.length) {
                break;
            }
            String str3 = this.h[i3];
            if (str3 != null) {
                bundle.putString("fh_".concat(Long.valueOf(jArr[i3]).toString()), str3);
            }
            i3++;
        }
        final com.google.android.gms.ads.internal.util.F f = com.google.android.gms.ads.internal.j.C.c;
        String str4 = this.c.a;
        f.getClass();
        bundle.putString("device", com.google.android.gms.ads.internal.util.F.I());
        C2601s7 c2601s7 = AbstractC2773w7.a;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        bundle.putString("eids", TextUtils.join(",", rVar.a.h()));
        boolean zIsEmpty = bundle.isEmpty();
        final Context context = this.a;
        if (zIsEmpty) {
            com.google.android.gms.ads.internal.util.client.i.d("Empty or null bundle.");
        } else {
            final String str5 = (String) rVar.c.a(AbstractC2773w7.Aa);
            boolean andSet = f.d.getAndSet(true);
            AtomicReference atomicReference = f.c;
            if (!andSet) {
                SharedPreferences.OnSharedPreferenceChangeListener onSharedPreferenceChangeListener = new SharedPreferences.OnSharedPreferenceChangeListener() { // from class: com.google.android.gms.ads.internal.util.D
                    @Override // android.content.SharedPreferences.OnSharedPreferenceChangeListener
                    public final void onSharedPreferenceChanged(SharedPreferences sharedPreferences, String str6) {
                        f.c.set(U2.d(context, str5));
                    }
                };
                if (TextUtils.isEmpty(str5)) {
                    bundleD = Bundle.EMPTY;
                } else {
                    PreferenceManager.getDefaultSharedPreferences(context).registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
                    bundleD = com.google.android.gms.internal.mlkit_vision_common.U2.d(context, str5);
                }
                atomicReference.set(bundleD);
            }
            bundle.putAll((Bundle) atomicReference.get());
        }
        com.google.android.gms.ads.internal.util.client.c cVar = C1614q.f.a;
        com.google.android.gms.ads.internal.util.client.c.m(context, str4, bundle, new androidx.compose.foundation.text.input.internal.u(context, false, str4, 9));
        this.o = true;
    }

    public final void d(AbstractC2656td abstractC2656td) {
        if (this.k && !this.l) {
            if (com.google.android.gms.ads.internal.util.A.m() && !this.l) {
                com.google.android.gms.ads.internal.util.A.l("VideoMetricsMixin first frame");
            }
            AbstractC2096gb.h(this.e, this.d, "vff2");
            this.l = true;
        }
        com.google.android.gms.ads.internal.j.C.k.getClass();
        long jNanoTime = System.nanoTime();
        if (this.m && this.p && this.q != -1) {
            double nanos = TimeUnit.SECONDS.toNanos(1L) / (jNanoTime - this.q);
            androidx.camera.camera2.internal.concurrent.a aVar = this.f;
            aVar.b++;
            int i = 0;
            while (true) {
                double[] dArr = (double[]) aVar.e;
                if (i >= dArr.length) {
                    break;
                }
                double d = dArr[i];
                if (d <= nanos && nanos < ((double[]) aVar.d)[i]) {
                    int[] iArr = (int[]) aVar.f;
                    iArr[i] = iArr[i] + 1;
                }
                if (nanos < d) {
                    break;
                } else {
                    i++;
                }
            }
        }
        this.p = this.m;
        this.q = jNanoTime;
        long jLongValue = ((Long) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.I)).longValue();
        long j = abstractC2656td.j();
        int i2 = 0;
        while (true) {
            String[] strArr = this.h;
            if (i2 >= strArr.length) {
                return;
            }
            if (strArr[i2] == null && jLongValue > Math.abs(j - this.g[i2])) {
                int i3 = 8;
                Bitmap bitmap = abstractC2656td.getBitmap(8, 8);
                long j2 = 63;
                int i4 = 0;
                long j3 = 0;
                while (i4 < i3) {
                    int i5 = 0;
                    while (i5 < i3) {
                        int pixel = bitmap.getPixel(i5, i4);
                        j3 |= (Color.green(pixel) + (Color.red(pixel) + Color.blue(pixel)) > 128 ? 1L : 0L) << ((int) j2);
                        j2--;
                        i5++;
                        i3 = 8;
                    }
                    i4++;
                    i3 = 8;
                }
                strArr[i2] = String.format("%016X", Long.valueOf(j3));
                return;
            }
            i2++;
        }
    }
}
