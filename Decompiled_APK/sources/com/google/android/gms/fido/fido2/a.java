package com.google.android.gms.fido.fido2;

import android.content.Context;
import android.os.Looper;
import androidx.annotation.NonNull;
import com.google.android.gms.common.api.d;
import com.google.android.gms.common.api.e;

/* loaded from: classes2.dex */
public class a extends e {
    public static final com.quizlet.data.repository.activitycenter.b l = new com.quizlet.data.repository.activitycenter.b("Fido.FIDO2_API", new com.google.android.gms.auth.api.b(7), new com.google.mlkit.common.sdkinternal.b(9));

    @Deprecated
    public a(@NonNull Context context) {
        super(context, null, l, com.google.android.gms.common.api.b.M0, new d(new com.google.mlkit.common.sdkinternal.model.a(9), Looper.getMainLooper()));
    }
}
