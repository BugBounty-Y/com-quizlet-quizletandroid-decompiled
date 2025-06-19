package com.google.android.gms.internal.ads;

import android.os.Bundle;
import com.google.android.gms.measurement.internal.BinderC3869g0;
import com.google.android.gms.measurement.internal.InterfaceC3901x;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;

/* renamed from: com.google.android.gms.internal.ads.Vd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class RunnableC1788Vd implements Runnable {
    public final /* synthetic */ int a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;
    public final Object f;

    public /* synthetic */ RunnableC1788Vd(C1721Kc c1721Kc, Throwable th, C2584rr c2584rr, String str, com.google.android.gms.auth.api.signin.internal.h hVar) {
        this.a = 1;
        this.c = c1721Kc;
        this.d = th;
        this.e = c2584rr;
        this.b = str;
        this.f = hVar;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Removed duplicated region for block: B:162:0x0320  */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() throws java.lang.Exception {
        /*
            Method dump skipped, instructions count: 932
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.RunnableC1788Vd.run():void");
    }

    public /* synthetic */ RunnableC1788Vd(C1931cl c1931cl, String str, BinderC1888bl binderC1888bl, C2369mq c2369mq, ArrayList arrayList) {
        this.a = 2;
        this.c = c1931cl;
        this.b = str;
        this.d = binderC1888bl;
        this.e = c2369mq;
        this.f = arrayList;
    }

    public /* synthetic */ RunnableC1788Vd(BinderC3869g0 binderC3869g0, com.google.android.gms.measurement.internal.zzr zzrVar, Bundle bundle, InterfaceC3901x interfaceC3901x, String str) {
        this.a = 3;
        this.c = binderC3869g0;
        this.d = zzrVar;
        this.e = bundle;
        this.f = interfaceC3901x;
        this.b = str;
    }

    public RunnableC1788Vd(com.google.android.gms.measurement.internal.Y0 y0, AtomicReference atomicReference, String str, String str2, com.google.android.gms.measurement.internal.zzr zzrVar) {
        this.a = 4;
        this.d = atomicReference;
        this.b = str;
        this.c = str2;
        this.e = zzrVar;
        this.f = y0;
    }

    public /* synthetic */ RunnableC1788Vd(Object obj, Object obj2, Object obj3, Object obj4, Object obj5, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
        this.e = obj4;
        this.f = obj5;
    }

    public /* synthetic */ RunnableC1788Vd(Object obj, String str, String str2, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = str;
        this.c = str2;
        this.d = obj2;
        this.e = obj3;
        this.f = obj;
    }
}
