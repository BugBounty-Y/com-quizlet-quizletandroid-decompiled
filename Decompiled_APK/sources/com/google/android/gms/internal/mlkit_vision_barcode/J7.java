package com.google.android.gms.internal.mlkit_vision_barcode;

import android.content.Context;
import android.os.SystemClock;
import androidx.appcompat.view.menu.RunnableC0069f;
import com.google.android.gms.common.internal.C1658h;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/* loaded from: classes2.dex */
public final class J7 {
    public static B k;
    public static final G l;
    public final String a;
    public final String b;
    public final H7 c;
    public final com.google.mlkit.common.sdkinternal.i d;
    public final com.google.android.gms.tasks.m e;
    public final com.google.android.gms.tasks.m f;
    public final String g;
    public final int h;
    public final HashMap i = new HashMap();
    public final HashMap j = new HashMap();

    static {
        Object[] objArr = {"optional-module-barcode", "com.google.android.gms.vision.barcode"};
        Objects.requireNonNull(objArr[0]);
        Objects.requireNonNull(objArr[1]);
        l = new G(objArr, 0);
    }

    public J7(Context context, com.google.mlkit.common.sdkinternal.i iVar, H7 h7, String str) {
        this.a = context.getPackageName();
        this.b = com.google.mlkit.common.sdkinternal.c.a(context);
        this.d = iVar;
        this.c = h7;
        N7.b();
        this.g = str;
        com.google.mlkit.common.sdkinternal.e eVarA = com.google.mlkit.common.sdkinternal.e.a();
        androidx.camera.core.impl.utils.executor.c cVar = new androidx.camera.core.impl.utils.executor.c(this, 10);
        eVarA.getClass();
        this.e = com.google.mlkit.common.sdkinternal.e.b(cVar);
        com.google.mlkit.common.sdkinternal.e eVarA2 = com.google.mlkit.common.sdkinternal.e.a();
        Objects.requireNonNull(iVar);
        com.google.android.gms.internal.mlkit_common.p pVar = new com.google.android.gms.internal.mlkit_common.p(iVar, 1);
        eVarA2.getClass();
        this.f = com.google.mlkit.common.sdkinternal.e.b(pVar);
        G g = l;
        this.h = g.containsKey(str) ? com.google.android.gms.dynamite.c.d(context, (String) g.get(str), false) : -1;
    }

    public static long a(double d, ArrayList arrayList) {
        return ((Long) arrayList.get(Math.max(((int) Math.ceil((d / 100.0d) * arrayList.size())) - 1, 0))).longValue();
    }

    public final void b(I7 i7, EnumC3298x5 enumC3298x5) {
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        if (d(enumC3298x5, jElapsedRealtime)) {
            this.i.put(enumC3298x5, Long.valueOf(jElapsedRealtime));
            com.google.mlkit.common.sdkinternal.k.a.execute(new RunnableC0069f(12, this, i7.zza(), enumC3298x5, c(), false));
        }
    }

    public final String c() {
        com.google.android.gms.tasks.m mVar = this.e;
        return mVar.l() ? (String) mVar.h() : C1658h.c.a(this.g);
    }

    public final boolean d(EnumC3298x5 enumC3298x5, long j) {
        HashMap map = this.i;
        return map.get(enumC3298x5) == null || j - ((Long) map.get(enumC3298x5)).longValue() > TimeUnit.SECONDS.toMillis(30L);
    }
}
