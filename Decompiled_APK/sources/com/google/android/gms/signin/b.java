package com.google.android.gms.signin;

import com.google.android.gms.common.api.Scope;

/* loaded from: classes2.dex */
public abstract class b {
    public static final com.google.android.gms.auth.api.b a;

    static {
        com.google.mlkit.common.sdkinternal.b bVar = new com.google.mlkit.common.sdkinternal.b(9);
        com.google.android.gms.auth.api.b bVar2 = new com.google.android.gms.auth.api.b(9);
        a = bVar2;
        new Scope(1, "profile");
        new Scope(1, "email");
        new com.quizlet.data.repository.activitycenter.b("SignIn.API", bVar2, bVar);
    }
}
