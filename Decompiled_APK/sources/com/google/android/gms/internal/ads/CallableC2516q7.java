package com.google.android.gms.internal.ads;

import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import java.util.HashMap;
import java.util.concurrent.Callable;
import org.json.JSONObject;

/* renamed from: com.google.android.gms.internal.ads.q7, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class CallableC2516q7 implements Callable {
    public final /* synthetic */ int a;

    @Override // java.util.concurrent.Callable
    public final Object call() {
        String str;
        switch (this.a) {
            case 0:
                return Boolean.valueOf("mounted".equals(Environment.getExternalStorageState()));
            case 1:
                com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
                jVar.k.getClass();
                return new C2882yo(System.currentTimeMillis() - jVar.h.d().n().f);
            case 2:
                com.google.android.gms.ads.internal.j jVar2 = com.google.android.gms.ads.internal.j.C;
                androidx.camera.camera2.interop.c cVar = jVar2.o;
                synchronized (cVar.a) {
                    str = (String) cVar.e;
                }
                return new C2324lo(jVar2.o.h(), 1, str);
            case 3:
                Bundle bundle = new Bundle();
                Runtime runtime = Runtime.getRuntime();
                bundle.putLong("runtime_free", runtime.freeMemory());
                bundle.putLong("runtime_max", runtime.maxMemory());
                bundle.putLong("runtime_total", runtime.totalMemory());
                bundle.putInt("web_view_count", com.google.android.gms.ads.internal.j.C.h.j.get());
                return new C2196io(bundle, 1);
            case 4:
                return new Ho(new JSONObject(), 1);
            case 5:
                HashMap map = new HashMap();
                C2601s7 c2601s7 = AbstractC2773w7.Q;
                com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
                String str2 = (String) rVar.c.a(c2601s7);
                if (str2 != null && !str2.isEmpty()) {
                    if (Build.VERSION.SDK_INT >= ((Integer) rVar.c.a(AbstractC2773w7.R)).intValue()) {
                        for (String str3 : str2.split(",", -1)) {
                            map.put(str3, com.google.android.gms.ads.internal.util.z.a(str3));
                        }
                    }
                }
                return new Ho(map, 3);
            default:
                return null;
        }
    }
}
