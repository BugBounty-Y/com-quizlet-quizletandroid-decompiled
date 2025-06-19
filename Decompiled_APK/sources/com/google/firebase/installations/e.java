package com.google.firebase.installations;

/* loaded from: classes2.dex */
public final class e implements h {
    public final i a;
    public final com.google.android.gms.tasks.f b;

    public e(i iVar, com.google.android.gms.tasks.f fVar) {
        this.a = iVar;
        this.b = fVar;
    }

    @Override // com.google.firebase.installations.h
    public final boolean a(com.google.firebase.installations.local.a aVar) {
        if (aVar.b != 4 || this.a.a(aVar)) {
            return false;
        }
        String str = aVar.c;
        if (str == null) {
            throw new NullPointerException("Null token");
        }
        this.b.b(new a(aVar.e, aVar.f, str));
        return true;
    }

    @Override // com.google.firebase.installations.h
    public final boolean b(Exception exc) {
        this.b.c(exc);
        return true;
    }
}
