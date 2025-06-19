package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class Vn implements Uo {
    public final /* synthetic */ int a;
    public final boolean b;

    public /* synthetic */ Vn(boolean z, int i) {
        this.a = i;
        this.b = z;
    }

    private final /* synthetic */ void a(Object obj) {
    }

    private final /* synthetic */ void d(Object obj) {
    }

    private final /* synthetic */ void e(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
        switch (this.a) {
            case 2:
                ((Og) obj).b.putBoolean("is_gbid", this.b);
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void c(Object obj) {
        switch (this.a) {
            case 0:
                ((Og) obj).a.putString("adid_p", true != this.b ? "0" : "1");
                break;
            case 1:
                ((Og) obj).a.putBoolean("ibrr", this.b);
                break;
            case 2:
                ((Og) obj).a.putBoolean("is_gbid", this.b);
                break;
            default:
                Og og = (Og) obj;
                if (this.b) {
                    og.a.putBoolean("sdk_prefetch", true);
                    break;
                }
                break;
        }
    }
}
