package com.google.android.gms.common.internal;

import android.accounts.Account;
import android.content.Context;
import android.os.Looper;
import androidx.camera.camera2.internal.c0;
import com.google.android.gms.common.GoogleApiAvailability;
import com.google.android.gms.common.api.Scope;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.Executor;

/* renamed from: com.google.android.gms.common.internal.f, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC1656f extends AbstractC1655e implements com.google.android.gms.common.api.c {
    public final Set z;

    /* JADX WARN: Illegal instructions before constructor call */
    public AbstractC1656f(Context context, Looper looper, int i, c0 c0Var, com.google.android.gms.common.api.f fVar, com.google.android.gms.common.api.g gVar) {
        E eA = E.a(context);
        GoogleApiAvailability googleApiAvailability = GoogleApiAvailability.d;
        u.h(fVar);
        u.h(gVar);
        super(context, looper, eA, googleApiAvailability, i, new i(fVar), new i(gVar), (String) c0Var.e);
        Set set = (Set) c0Var.c;
        Iterator it2 = set.iterator();
        while (it2.hasNext()) {
            if (!set.contains((Scope) it2.next())) {
                throw new IllegalStateException("Expanding scopes is not permitted, use implied scopes instead");
            }
        }
        this.z = set;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Account g() {
        return null;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Executor i() {
        return null;
    }

    @Override // com.google.android.gms.common.internal.AbstractC1655e
    public final Set l() {
        return this.z;
    }
}
