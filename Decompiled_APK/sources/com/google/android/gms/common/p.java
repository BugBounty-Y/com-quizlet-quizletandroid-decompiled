package com.google.android.gms.common;

/* loaded from: classes2.dex */
public final class p extends h {
    public final o d;

    public /* synthetic */ p(o oVar) {
        super(false, null, null);
        this.d = oVar;
    }

    @Override // com.google.android.gms.common.h
    public final void a() {
        try {
            this.d.call();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
