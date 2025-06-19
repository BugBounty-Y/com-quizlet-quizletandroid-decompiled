package com.onetrust.otpublishers.headless.UI.mobiledatautils;

import androidx.fragment.app.I;
import androidx.lifecycle.A;
import androidx.lifecycle.H;
import androidx.lifecycle.J;
import com.google.android.material.bottomsheet.i;

/* loaded from: classes2.dex */
public final class a implements H {
    public final /* synthetic */ i a;
    public final /* synthetic */ I b;
    public final /* synthetic */ String c;

    public a(i iVar, I i, String str) {
        this.a = iVar;
        this.b = i;
        this.c = str;
    }

    @Override // androidx.lifecycle.H
    public final void d(J j, A a) {
        if (a.compareTo(A.ON_RESUME) == 0) {
            i iVar = this.a;
            I i = this.b;
            iVar.O(i.getSupportFragmentManager(), this.c);
            i.getLifecycle().b(this);
        }
    }
}
