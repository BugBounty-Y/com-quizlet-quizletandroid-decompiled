package com.google.android.gms.auth.api.signin.internal;

import android.accounts.Account;
import android.content.Context;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Looper;
import androidx.camera.camera2.internal.c0;
import androidx.camera.camera2.internal.t0;
import com.google.android.gms.auth.api.signin.GoogleSignInOptions;
import com.google.android.gms.common.api.Scope;
import com.google.android.gms.common.api.internal.n;
import com.google.android.gms.common.internal.AbstractC1656f;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/* loaded from: classes2.dex */
public final class d extends AbstractC1656f {
    public final GoogleSignInOptions A;

    public d(Context context, Looper looper, c0 c0Var, GoogleSignInOptions googleSignInOptions, n nVar, n nVar2) {
        super(context, looper, 91, c0Var, nVar, nVar2);
        t0 t0Var = googleSignInOptions != null ? new t0(googleSignInOptions) : new t0();
        t0Var.i = com.google.android.gms.internal.p000authapi.f.a();
        Set<Scope> set = (Set) c0Var.c;
        if (!set.isEmpty()) {
            for (Scope scope : set) {
                HashSet hashSet = (HashSet) t0Var.d;
                hashSet.add(scope);
                hashSet.addAll(Arrays.asList(new Scope[0]));
            }
        }
        Scope scope2 = GoogleSignInOptions.p;
        HashSet hashSet2 = (HashSet) t0Var.d;
        if (hashSet2.contains(scope2)) {
            Scope scope3 = GoogleSignInOptions.o;
            if (hashSet2.contains(scope3)) {
                hashSet2.remove(scope3);
            }
        }
        if (t0Var.c && (((Account) t0Var.f) == null || !hashSet2.isEmpty())) {
            ((HashSet) t0Var.d).add(GoogleSignInOptions.n);
        }
        this.A = new GoogleSignInOptions(3, new ArrayList(hashSet2), (Account) t0Var.f, t0Var.c, t0Var.a, t0Var.b, (String) t0Var.e, (String) t0Var.g, (HashMap) t0Var.h, (String) t0Var.i);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e, com.google.android.gms.common.api.c
    public final int a() {
        return 12451000;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final IInterface d(IBinder iBinder) {
        if (iBinder == null) {
            return null;
        }
        IInterface iInterfaceQueryLocalInterface = iBinder.queryLocalInterface("com.google.android.gms.auth.api.signin.internal.ISignInService");
        return iInterfaceQueryLocalInterface instanceof j ? (j) iInterfaceQueryLocalInterface : new j(iBinder, "com.google.android.gms.auth.api.signin.internal.ISignInService", 1);
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String n() {
        return "com.google.android.gms.auth.api.signin.internal.ISignInService";
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final String o() {
        return "com.google.android.gms.auth.api.signin.service.START";
    }
}
