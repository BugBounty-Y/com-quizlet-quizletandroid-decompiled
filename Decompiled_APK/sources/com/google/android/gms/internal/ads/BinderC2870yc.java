package com.google.android.gms.internal.ads;

import com.google.android.gms.ads.internal.client.zze;

/* renamed from: com.google.android.gms.internal.ads.yc, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class BinderC2870yc extends AbstractBinderC2698uc {
    public final /* synthetic */ int a;
    public final com.google.android.gms.ads.w b;
    public final Object c;

    public /* synthetic */ BinderC2870yc(com.google.android.gms.ads.w wVar, Object obj, int i) {
        this.a = i;
        this.b = wVar;
        this.c = obj;
    }

    private final void e4(int i) {
    }

    private final void f4(int i) {
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void h() {
        C1667Bc c1667Bc;
        switch (this.a) {
            case 0:
                C2578rl c2578rl = (C2578rl) this.b;
                if (c2578rl != null) {
                    c2578rl.b((C2827xc) this.c);
                    break;
                }
                break;
            default:
                C2578rl c2578rl2 = (C2578rl) this.b;
                if (c2578rl2 != null && (c1667Bc = (C1667Bc) this.c) != null) {
                    c2578rl2.b(c1667Bc);
                    break;
                }
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void r(zze zzeVar) {
        switch (this.a) {
            case 0:
                C2578rl c2578rl = (C2578rl) this.b;
                if (c2578rl != null) {
                    c2578rl.a(zzeVar.b());
                    break;
                }
                break;
            default:
                C2578rl c2578rl2 = (C2578rl) this.b;
                if (c2578rl2 != null) {
                    c2578rl2.a(zzeVar.b());
                    break;
                }
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2741vc
    public final void u(int i) {
        int i2 = this.a;
    }
}
