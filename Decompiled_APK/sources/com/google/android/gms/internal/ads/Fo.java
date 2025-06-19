package com.google.android.gms.internal.ads;

import android.os.Bundle;

/* loaded from: classes2.dex */
public final class Fo implements Uo {
    public final /* synthetic */ int a;
    public final Boolean b;

    public /* synthetic */ Fo(int i, Boolean bool) {
        this.a = i;
        this.b = bool;
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
                Boolean bool = this.b;
                if (bool != null) {
                    og.a.putBoolean("hw_accel", bool.booleanValue());
                    break;
                }
                break;
            default:
                Bundle bundle = ((Og) obj).a;
                Boolean bool2 = this.b;
                if (bool2 != null) {
                    if (!bool2.booleanValue()) {
                        bundle.putInt("lft", 0);
                        break;
                    } else {
                        bundle.putInt("lft", 1);
                        break;
                    }
                } else {
                    bundle.putInt("lft", -1);
                    break;
                }
        }
    }
}
