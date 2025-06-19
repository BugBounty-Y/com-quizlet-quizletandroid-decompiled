package com.quizlet.billing.subscriptions;

import androidx.camera.camera2.internal.T;
import com.android.billingclient.api.Purchase;
import io.reactivex.rxjava3.subjects.r;

/* loaded from: classes2.dex */
public final /* synthetic */ class e implements io.reactivex.rxjava3.functions.j {
    public final /* synthetic */ h a;
    public final /* synthetic */ Purchase b;
    public final /* synthetic */ String c;
    public final /* synthetic */ long d;
    public final /* synthetic */ String e;

    public /* synthetic */ e(long j, Purchase purchase, h hVar, String str, String str2) {
        this.a = hVar;
        this.b = purchase;
        this.c = str;
        this.d = j;
        this.e = str2;
    }

    @Override // io.reactivex.rxjava3.functions.j
    public final Object get() {
        h hVar = this.a;
        r rVar = hVar.i.g;
        Purchase purchase = this.b;
        String str = this.c;
        io.reactivex.rxjava3.internal.operators.single.g gVarG = rVar.g(new T(hVar, purchase, str, 19));
        long j = this.d;
        String str2 = this.e;
        return gVarG.e(new com.google.android.datatransport.runtime.scheduling.jobscheduling.h(hVar, j, purchase, str2)).e(new g(j, purchase, hVar, str, str2));
    }
}
