package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.k6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2257k6 extends C2313ld {
    public final /* synthetic */ int b = 0;
    public final Object c;

    public C2257k6(com.bumptech.glide.manager.p pVar) {
        this.c = pVar;
    }

    @Override // com.google.android.gms.internal.ads.C2313ld, java.util.concurrent.Future
    public boolean cancel(boolean z) {
        switch (this.b) {
            case 0:
                com.bumptech.glide.manager.p.i((com.bumptech.glide.manager.p) this.c);
                return this.a.cancel(z);
            default:
                return super.cancel(z);
        }
    }

    public void e() {
        c(this.c);
    }

    public C2257k6(Object obj) {
        this.c = obj;
    }
}
