package com.google.android.gms.internal.appset;

import android.content.Context;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.k;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;

/* loaded from: classes2.dex */
public final class f extends com.google.android.gms.common.api.e implements com.google.android.gms.appset.a {
    public static final com.quizlet.data.repository.activitycenter.b n = new com.quizlet.data.repository.activitycenter.b("AppSet.API", new com.google.android.gms.auth.api.b(4), new com.google.mlkit.common.sdkinternal.b(9));
    public final Context l;
    public final com.google.android.gms.common.c m;

    public f(Context context, com.google.android.gms.common.c cVar) {
        super(context, null, n, com.google.android.gms.common.api.b.M0, com.google.android.gms.common.api.d.c);
        this.l = context;
        this.m = cVar;
    }

    @Override // com.google.android.gms.appset.a
    public final Task b() {
        if (this.m.c(this.l, 212800000) != 0) {
            return S3.h(new ApiException(new Status(17, null, null, null)));
        }
        k kVarA = AbstractC2027eu.a();
        kVarA.e = new Feature[]{com.google.android.gms.appset.c.a};
        kVarA.d = new retrofit2.adapter.rxjava3.d(this);
        kVarA.c = false;
        kVarA.b = 27601;
        return c(0, kVarA.a());
    }
}
