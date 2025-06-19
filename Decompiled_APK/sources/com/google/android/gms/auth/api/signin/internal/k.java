package com.google.android.gms.auth.api.signin.internal;

import android.content.Context;
import android.os.Binder;
import android.os.IInterface;
import android.os.Looper;
import android.os.Parcel;
import android.text.TextUtils;
import androidx.appcompat.widget.C0122z;
import androidx.camera.camera2.internal.AbstractC0147y;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.common.api.Status;
import com.google.android.gms.common.api.internal.BasePendingResult;
import com.google.android.gms.common.api.internal.F;
import com.google.android.gms.common.api.internal.p;
import com.google.android.gms.common.internal.u;
import org.json.JSONException;

/* loaded from: classes2.dex */
public final class k extends com.google.android.gms.internal.p000authapi.g implements IInterface {
    public final Context b;

    public k(Context context) {
        super("com.google.android.gms.auth.api.signin.internal.IRevocationService", 0);
        this.b = context;
    }

    @Override // com.google.android.gms.internal.p000authapi.g
    public final boolean f3(int i, Parcel parcel, Parcel parcel2) {
        BasePendingResult basePendingResult;
        GoogleSignInOptions googleSignInOptionsA;
        String strE;
        Context context = this.b;
        if (i != 1) {
            if (i != 2) {
                return false;
            }
            v3();
            h.B(context).C();
            return true;
        }
        v3();
        a aVarA = a.a(context);
        GoogleSignInAccount googleSignInAccountB = aVarA.b();
        GoogleSignInOptions googleSignInOptions = GoogleSignInOptions.k;
        if (googleSignInAccountB != null) {
            String strE2 = aVarA.e("defaultGoogleSignInAccount");
            if (TextUtils.isEmpty(strE2) || (strE = aVarA.e(a.f("googleSignInOptions", strE2))) == null) {
                googleSignInOptionsA = null;
                googleSignInOptions = googleSignInOptionsA;
            } else {
                try {
                    googleSignInOptionsA = GoogleSignInOptions.a(strE);
                } catch (JSONException unused) {
                }
                googleSignInOptions = googleSignInOptionsA;
            }
        }
        GoogleSignInOptions googleSignInOptions2 = googleSignInOptions;
        u.h(googleSignInOptions2);
        com.google.android.gms.auth.api.signin.a aVar = new com.google.android.gms.auth.api.signin.a(context, null, com.google.android.gms.auth.api.a.a, googleSignInOptions2, new com.google.android.gms.common.api.d(new com.google.mlkit.common.sdkinternal.model.a(9), Looper.getMainLooper()));
        if (googleSignInAccountB != null) {
            aVar.d();
        } else {
            boolean z = aVar.e() == 3;
            C0122z c0122z = g.a;
            if (c0122z.b <= 3) {
                ((String) c0122z.d).concat("Signing out");
            }
            g.a(aVar.a);
            p pVar = aVar.i;
            if (z) {
                Status status = Status.e;
                BasePendingResult jVar = new com.google.android.gms.common.api.internal.j(pVar);
                jVar.setResult(status);
                basePendingResult = jVar;
            } else {
                f fVar = new f(pVar, 0);
                pVar.a(fVar);
                basePendingResult = fVar;
            }
            basePendingResult.addStatusListener(new F(basePendingResult, new com.google.android.gms.tasks.f(), new com.onetrust.otpublishers.headless.Internal.Helper.h(9)));
        }
        return true;
    }

    public final void v3() {
        if (!com.google.android.gms.common.util.c.k(this.b, Binder.getCallingUid())) {
            throw new SecurityException(AbstractC0147y.c(Binder.getCallingUid(), "Calling UID ", " is not Google Play services."));
        }
    }
}
