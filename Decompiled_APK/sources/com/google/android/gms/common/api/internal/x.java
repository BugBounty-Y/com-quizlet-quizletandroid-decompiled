package com.google.android.gms.common.api.internal;

import android.accounts.Account;
import android.content.Context;
import android.os.Parcel;
import android.os.RemoteException;
import android.util.Log;
import androidx.camera.camera2.internal.c0;
import androidx.camera.camera2.internal.p0;
import com.google.android.gms.auth.api.signin.GoogleSignInAccount;
import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.internal.zat;
import com.google.android.gms.internal.ads.Ls;
import com.google.android.gms.signin.internal.zai;
import com.google.android.gms.signin.internal.zak;
import java.util.Set;

/* loaded from: classes2.dex */
public final class x extends com.google.android.gms.signin.internal.b implements com.google.android.gms.common.api.f, com.google.android.gms.common.api.g {
    public static final com.google.android.gms.auth.api.b i = com.google.android.gms.signin.b.a;
    public final Context b;
    public final Ls c;
    public final com.google.android.gms.auth.api.b d;
    public final Set e;
    public final c0 f;
    public com.google.android.gms.signin.internal.a g;
    public p0 h;

    public x(Context context, Ls ls, c0 c0Var) {
        super("com.google.android.gms.signin.internal.ISignInCallbacks", 1);
        this.b = context;
        this.c = ls;
        this.f = c0Var;
        this.e = (Set) c0Var.b;
        this.d = i;
    }

    @Override // com.google.android.gms.common.api.f
    public final void V(int i2) {
        p0 p0Var = this.h;
        n nVar = (n) ((C1647e) p0Var.f).j.get((C1643a) p0Var.d);
        if (nVar != null) {
            if (nVar.i) {
                nVar.j(new ConnectionResult(17));
            } else {
                nVar.V(i2);
            }
        }
    }

    @Override // com.google.android.gms.common.api.f
    public final void X() {
        com.google.android.gms.signin.internal.a aVar = this.g;
        aVar.getClass();
        try {
            aVar.B.getClass();
            Account account = new Account("<<default account>>", "com.google");
            GoogleSignInAccount googleSignInAccountB = "<<default account>>".equals(account.name) ? com.google.android.gms.auth.api.signin.internal.a.a(aVar.c).b() : null;
            Integer num = aVar.D;
            com.google.android.gms.common.internal.u.h(num);
            zat zatVar = new zat(2, account, num.intValue(), googleSignInAccountB);
            com.google.android.gms.signin.internal.c cVar = (com.google.android.gms.signin.internal.c) aVar.m();
            zai zaiVar = new zai(1, zatVar);
            Parcel parcelObtain = Parcel.obtain();
            parcelObtain.writeInterfaceToken(cVar.c);
            com.google.android.gms.internal.base.a.b(parcelObtain, zaiVar);
            com.google.android.gms.internal.base.a.c(parcelObtain, this);
            cVar.V(12, parcelObtain);
        } catch (RemoteException e) {
            Log.w("SignInClientImpl", "Remote service probably died when signIn is called");
            try {
                this.c.post(new androidx.camera.core.impl.utils.futures.h(this, false, new zak(1, new ConnectionResult(8, null), null), 22));
            } catch (RemoteException unused) {
                Log.wtf("SignInClientImpl", "ISignInCallbacks#onSignInComplete should be executed from the same process, unexpected RemoteException.", e);
            }
        }
    }

    @Override // com.google.android.gms.common.api.g
    public final void f0(ConnectionResult connectionResult) {
        this.h.o(connectionResult);
    }
}
