package com.google.android.play.core.review;

import android.app.PendingIntent;
import android.os.Bundle;
import com.android.billingclient.api.C1472a;
import com.google.android.gms.internal.p000authapi.g;
import com.google.android.gms.tasks.f;
import com.google.android.play.core.review.internal.h;
import com.google.android.play.core.review.internal.j;

/* loaded from: classes2.dex */
public final class c extends g {
    public final C1472a b;
    public final f c;
    public final /* synthetic */ d d;

    public c(d dVar, f fVar) {
        C1472a c1472a = new C1472a("OnRequestInstallCallback", 1);
        this.d = dVar;
        super(6);
        attachInterface(this, "com.google.android.play.core.inappreview.protocol.IInAppReviewServiceCallback");
        this.b = c1472a;
        this.c = fVar;
    }

    public final void v3(Bundle bundle) {
        j jVar = this.d.a;
        if (jVar != null) {
            f fVar = this.c;
            synchronized (jVar.f) {
                jVar.e.remove(fVar);
            }
            jVar.a().post(new h(jVar, 0));
        }
        this.b.a("onGetLaunchReviewFlowInfo", new Object[0]);
        this.c.d(new zza((PendingIntent) bundle.get("confirmation_intent"), bundle.getBoolean("is_review_no_op")));
    }
}
