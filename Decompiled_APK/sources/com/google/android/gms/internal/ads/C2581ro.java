package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.ro, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2581ro implements Uo {
    public final /* synthetic */ int a;
    public final Integer b;

    public /* synthetic */ C2581ro(int i, Integer num) {
        this.a = i;
        this.b = num;
    }

    private final /* synthetic */ void a(Object obj) {
    }

    private final /* synthetic */ void d(Object obj) {
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* synthetic */ void b(Object obj) {
        int i = this.a;
    }

    @Override // com.google.android.gms.internal.ads.Uo
    public final /* bridge */ /* synthetic */ void c(Object obj) {
        switch (this.a) {
            case 0:
                Og og = (Og) obj;
                Integer num = this.b;
                if (num != null) {
                    og.a.putInt("aos", num.intValue());
                    break;
                }
                break;
            default:
                Og og2 = (Og) obj;
                Integer num2 = this.b;
                if (num2 != null) {
                    og2.a.putInt("dspct", Math.min(num2.intValue(), 20));
                    break;
                }
                break;
        }
    }
}
