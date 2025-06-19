package com.google.android.gms.auth.api.identity;

import com.google.android.gms.auth.api.identity.BeginSignInRequest;

/* loaded from: classes2.dex */
public final class a {
    public boolean a;
    public String b;
    public boolean c;

    public final BeginSignInRequest.GoogleIdTokenRequestOptions a() {
        return new BeginSignInRequest.GoogleIdTokenRequestOptions(this.a, this.b, null, this.c, null, null, false);
    }
}
