package com.auth0.android.jwt;

import com.google.gson.m;
import com.google.gson.p;

/* loaded from: classes.dex */
public final class b extends a {
    public final m a;

    public b(m mVar) {
        this.a = mVar;
    }

    @Override // com.auth0.android.jwt.a
    public final Long a() {
        m mVar = this.a;
        mVar.getClass();
        if (mVar instanceof p) {
            return Long.valueOf(mVar.a());
        }
        return null;
    }

    @Override // com.auth0.android.jwt.a
    public final String b() {
        m mVar = this.a;
        mVar.getClass();
        if (mVar instanceof p) {
            return mVar.b();
        }
        return null;
    }
}
