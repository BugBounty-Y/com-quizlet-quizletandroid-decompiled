package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.rl, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2578rl extends com.google.android.gms.ads.w {
    public final /* synthetic */ int c;
    public final /* synthetic */ String d;
    public final /* synthetic */ String e;
    public final /* synthetic */ BinderC2707ul f;

    public /* synthetic */ C2578rl(BinderC2707ul binderC2707ul, String str, String str2, int i) {
        this.c = i;
        this.d = str;
        this.e = str2;
        this.f = binderC2707ul;
    }

    @Override // com.google.android.gms.ads.w
    public final void a(com.google.android.gms.ads.l lVar) {
        switch (this.c) {
            case 0:
                this.f.i4(BinderC2707ul.h4(lVar), this.e);
                break;
            case 1:
                this.f.i4(BinderC2707ul.h4(lVar), this.e);
                break;
            default:
                this.f.i4(BinderC2707ul.h4(lVar), this.e);
                break;
        }
    }

    @Override // com.google.android.gms.ads.w
    public final /* bridge */ /* synthetic */ void b(Object obj) {
        switch (this.c) {
            case 0:
                this.f.e4(this.d, this.e, (V5) obj);
                break;
            case 1:
                this.f.e4(this.d, this.e, (C2827xc) obj);
                break;
            default:
                this.f.e4(this.d, this.e, (C1667Bc) obj);
                break;
        }
    }
}
