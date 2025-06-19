package com.google.android.gms.internal.ads;

import android.os.Bundle;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class Xn implements Uo {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public final Object d;

    public /* synthetic */ Xn(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    private final /* synthetic */ void a(Object obj) {
    }

    private final /* synthetic */ void d(Object obj) {
    }

    private final /* synthetic */ void e(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final void b(Object obj) {
        int i;
        switch (this.a) {
            case 2:
                C2023eq c2023eq = (C2023eq) this.b;
                ArrayList arrayList = c2023eq.g;
                Og og = (Og) obj;
                if (arrayList != null && !arrayList.isEmpty()) {
                    Bundle bundle = og.b;
                    zzbfv zzbfvVar = c2023eq.i;
                    if (zzbfvVar != null && (i = zzbfvVar.i) != 0) {
                        bundle.putBoolean("sccg_tap", zzbfvVar.j);
                        bundle.putInt("sccg_dir", i);
                        break;
                    }
                }
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x004e A[Catch: JSONException -> 0x0061, TryCatch #0 {JSONException -> 0x0061, blocks: (B:5:0x0007, B:8:0x0015, B:10:0x001b, B:18:0x0043, B:19:0x004e, B:21:0x0054), top: B:178:0x0007 }] */
    @Override // com.google.android.gms.internal.ads.Uo
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void c(java.lang.Object r11) throws org.json.JSONException {
        /*
            Method dump skipped, instructions count: 758
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Xn.c(java.lang.Object):void");
    }
}
