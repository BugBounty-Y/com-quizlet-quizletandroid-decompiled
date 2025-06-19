package com.google.firebase.installations;

/* loaded from: classes2.dex */
public final class f implements h {
    public final com.google.android.gms.tasks.f a;

    public f(com.google.android.gms.tasks.f fVar) {
        this.a = fVar;
    }

    @Override // com.google.firebase.installations.h
    public final boolean a(com.google.firebase.installations.local.a aVar) {
        int i = aVar.b;
        if (i != 3 && i != 4 && i != 5) {
            return false;
        }
        this.a.d(aVar.a);
        return true;
    }

    @Override // com.google.firebase.installations.h
    public final boolean b(Exception exc) {
        return false;
    }
}
