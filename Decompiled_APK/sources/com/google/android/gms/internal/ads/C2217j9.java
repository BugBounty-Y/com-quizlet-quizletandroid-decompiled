package com.google.android.gms.internal.ads;

import android.view.View;
import java.lang.ref.WeakReference;
import java.util.HashMap;

/* renamed from: com.google.android.gms.internal.ads.j9, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class C2217j9 implements InterfaceC2389n9 {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;

    public /* synthetic */ C2217j9(int i, Object obj, Object obj2) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
    }

    public void a(String str, InterfaceC2775w9 interfaceC2775w9) {
        synchronized (this.b) {
            ((HashMap) this.c).put(str, interfaceC2775w9);
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:113:0x0270  */
    @Override // com.google.android.gms.internal.ads.InterfaceC2389n9
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void e(java.lang.Object r10, java.util.Map r11) {
        /*
            Method dump skipped, instructions count: 764
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2217j9.e(java.lang.Object, java.util.Map):void");
    }

    public C2217j9() {
        this.a = 2;
        this.b = new Object();
        this.c = new HashMap();
    }

    public C2217j9(Ki ki, View view) {
        this.a = 3;
        this.b = new WeakReference(ki);
        if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.Pc)).booleanValue()) {
            this.c = new WeakReference(view);
        } else {
            this.c = new WeakReference(null);
        }
    }
}
