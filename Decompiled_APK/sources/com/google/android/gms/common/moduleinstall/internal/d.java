package com.google.android.gms.common.moduleinstall.internal;

import android.content.Context;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.i;
import com.google.android.gms.common.api.internal.k;
import com.google.android.gms.common.internal.u;
import com.google.android.gms.common.moduleinstall.ModuleAvailabilityResponse;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.m;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class d extends com.google.android.gms.common.api.e {
    public static final com.quizlet.data.repository.activitycenter.b l = new com.quizlet.data.repository.activitycenter.b("ModuleInstall.API", new com.google.android.gms.auth.api.b(3), new com.google.mlkit.common.sdkinternal.b(9));

    public d(Context context) {
        super(context, null, l, com.google.android.gms.common.api.b.M0, com.google.android.gms.common.api.d.c);
    }

    public final m d(i... iVarArr) {
        u.a("Please provide at least one OptionalModuleApi.", iVarArr.length > 0);
        for (i iVar : iVarArr) {
            u.i(iVar, "Requested API must not be null.");
        }
        ApiFeatureRequest apiFeatureRequestA = ApiFeatureRequest.a(Arrays.asList(iVarArr), false);
        if (apiFeatureRequestA.a.isEmpty()) {
            return S3.i(new ModuleAvailabilityResponse(true, 0));
        }
        k kVarA = AbstractC2027eu.a();
        kVarA.e = new Feature[]{com.google.android.gms.internal.base.b.c};
        kVarA.b = 27301;
        kVarA.c = false;
        kVarA.d = new com.google.android.gms.internal.instantapps.a(25, this, apiFeatureRequestA);
        return c(0, kVarA.a());
    }
}
