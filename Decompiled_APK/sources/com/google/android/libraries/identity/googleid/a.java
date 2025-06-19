package com.google.android.libraries.identity.googleid;

import android.os.Bundle;
import androidx.credentials.q;
import com.google.android.gms.internal.mlkit_vision_common.T3;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class a extends q {
    public final String d;
    public final boolean e;
    public final boolean f;

    /* JADX WARN: Illegal instructions before constructor call */
    public a(String serverClientId, boolean z) {
        Intrinsics.checkNotNullParameter(serverClientId, "serverClientId");
        Bundle requestData = T3.b(serverClientId, z);
        Bundle candidateQueryData = T3.b(serverClientId, z);
        M allowedProviders = M.a;
        Intrinsics.checkNotNullParameter("com.google.android.libraries.identity.googleid.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL", DBUserFields.Names.USER_UPGRADE_TYPE);
        Intrinsics.checkNotNullParameter(requestData, "requestData");
        Intrinsics.checkNotNullParameter(candidateQueryData, "candidateQueryData");
        Intrinsics.checkNotNullParameter(allowedProviders, "allowedProviders");
        super(requestData, candidateQueryData, z, allowedProviders, com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR);
        this.d = serverClientId;
        this.e = true;
        this.f = z;
        if (serverClientId.length() <= 0) {
            throw new IllegalArgumentException("serverClientId should not be empty");
        }
    }
}
