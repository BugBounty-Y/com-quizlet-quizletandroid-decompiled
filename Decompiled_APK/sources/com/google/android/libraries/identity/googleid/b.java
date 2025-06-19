package com.google.android.libraries.identity.googleid;

import android.os.Bundle;
import androidx.credentials.q;
import com.google.android.gms.internal.mlkit_vision_common.U3;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import kotlin.collections.M;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class b extends q {
    public final String d;

    /* JADX WARN: Illegal instructions before constructor call */
    public b(String serverClientId) {
        Intrinsics.checkNotNullParameter(serverClientId, "serverClientId");
        Bundle requestData = U3.b(serverClientId);
        Bundle candidateQueryData = U3.b(serverClientId);
        M allowedProviders = M.a;
        Intrinsics.checkNotNullParameter("com.google.android.libraries.identity.googleid.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL", DBUserFields.Names.USER_UPGRADE_TYPE);
        Intrinsics.checkNotNullParameter(requestData, "requestData");
        Intrinsics.checkNotNullParameter(candidateQueryData, "candidateQueryData");
        Intrinsics.checkNotNullParameter(allowedProviders, "allowedProviders");
        super(requestData, candidateQueryData, true, allowedProviders, 2000);
        this.d = serverClientId;
        if (serverClientId.length() <= 0) {
            throw new IllegalArgumentException("serverClientId should not be empty");
        }
    }
}
