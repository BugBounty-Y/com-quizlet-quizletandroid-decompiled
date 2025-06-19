package com.google.android.gms.internal.p000authapi;

import android.content.Context;
import android.content.Intent;
import android.os.Parcelable;
import androidx.credentials.playservices.HiddenActivity;
import androidx.webkit.internal.p;
import com.google.android.gms.auth.api.identity.SignInCredential;
import com.google.android.gms.auth.api.identity.c;
import com.google.android.gms.common.Feature;
import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.d;
import com.google.android.gms.common.api.e;
import com.google.android.gms.common.api.h;
import com.google.android.gms.common.api.internal.C1647e;
import com.google.android.gms.common.api.internal.k;
import com.google.android.gms.internal.ads.AbstractC2027eu;
import com.google.android.gms.internal.mlkit_vision_common.AbstractC3495m3;
import com.google.android.gms.tasks.Task;
import java.util.Iterator;
import java.util.Set;

/* loaded from: classes2.dex */
public final class b extends e {
    public static final com.quizlet.data.repository.activitycenter.b m = new com.quizlet.data.repository.activitycenter.b("Auth.Api.Identity.CredentialSaving.API", new com.google.android.gms.auth.api.b(5), new com.google.mlkit.common.sdkinternal.b(9));
    public static final com.quizlet.data.repository.activitycenter.b n = new com.quizlet.data.repository.activitycenter.b("Auth.Api.Identity.SignIn.API", new com.google.android.gms.auth.api.b(6), new com.google.mlkit.common.sdkinternal.b(9));
    public final String l;

    public b(HiddenActivity hiddenActivity, c cVar) {
        super(hiddenActivity, hiddenActivity, m, cVar, d.c);
        this.l = f.a();
    }

    public SignInCredential d(Intent intent) throws ApiException {
        Status status = Status.g;
        if (intent == null) {
            throw new ApiException(status);
        }
        Parcelable.Creator<Status> creator = Status.CREATOR;
        byte[] byteArrayExtra = intent.getByteArrayExtra("status");
        Status status2 = (Status) (byteArrayExtra == null ? null : AbstractC3495m3.b(byteArrayExtra, creator));
        if (status2 == null) {
            throw new ApiException(Status.i);
        }
        if (!status2.a()) {
            throw new ApiException(status2);
        }
        Parcelable.Creator<SignInCredential> creator2 = SignInCredential.CREATOR;
        byte[] byteArrayExtra2 = intent.getByteArrayExtra("sign_in_credential");
        SignInCredential signInCredential = (SignInCredential) (byteArrayExtra2 != null ? AbstractC3495m3.b(byteArrayExtra2, creator2) : null);
        if (signInCredential != null) {
            return signInCredential;
        }
        throw new ApiException(status);
    }

    public Task e() {
        this.a.getSharedPreferences("com.google.android.gms.signin", 0).edit().clear().apply();
        Set set = h.a;
        synchronized (set) {
        }
        Iterator it2 = set.iterator();
        if (it2.hasNext()) {
            ((h) it2.next()).getClass();
            throw new UnsupportedOperationException();
        }
        C1647e.a();
        k kVarA = AbstractC2027eu.a();
        kVarA.e = new Feature[]{e.a};
        kVarA.d = new p(this, 18);
        kVarA.c = false;
        kVarA.b = 1554;
        return c(1, kVarA.a());
    }

    public b(HiddenActivity hiddenActivity, com.google.android.gms.auth.api.identity.h hVar) {
        super(hiddenActivity, hiddenActivity, n, hVar, d.c);
        this.l = f.a();
    }

    public b(Context context, com.google.android.gms.auth.api.identity.h hVar) {
        super(context, null, n, hVar, d.c);
        this.l = f.a();
    }
}
