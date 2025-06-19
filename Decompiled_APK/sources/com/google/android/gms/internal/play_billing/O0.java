package com.google.android.gms.internal.play_billing;

/* loaded from: classes2.dex */
public final class O0 implements InterfaceC3793e1 {
    public static final O0 b = new O0(0);
    public static final O0 c = new O0(1);
    public static final O0 d = new O0(2);
    public static final O0 e = new O0(3);
    public static final O0 f = new O0(4);
    public static final O0 g = new O0(5);
    public static final O0 h = new O0(6);
    public static final O0 i = new O0(7);
    public final /* synthetic */ int a;

    public /* synthetic */ O0(int i2) {
        this.a = i2;
    }

    @Override // com.google.android.gms.internal.play_billing.InterfaceC3793e1
    public final boolean zza(int i2) {
        switch (this.a) {
            case 0:
                switch (i2) {
                }
            case 1:
                switch (i2) {
                    default:
                        switch (i2) {
                        }
                    case 0:
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                    case 6:
                    case 7:
                    case 8:
                    case 9:
                    case 10:
                    case 11:
                    case 12:
                    case 13:
                    case 14:
                    case 15:
                        return true;
                }
            case 2:
                if (Z0.n(i2) != 0) {
                }
                break;
            case 3:
                if ((i2 != 0 ? i2 != 1 ? i2 != 2 ? i2 != 3 ? null : R1.ALTERNATIVE_BILLING_ACTION : R1.LOCAL_PURCHASES_UPDATED_ACTION : R1.PURCHASES_UPDATED_ACTION : R1.BROADCAST_ACTION_UNSPECIFIED) != null) {
                }
                break;
            case 4:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3) {
                }
                break;
            case 5:
                if (i2 != 17 && i2 != 18) {
                    switch (i2) {
                    }
                }
                break;
            case 6:
                if (i2 == 0 || i2 == 1 || i2 == 2 || i2 == 3 || i2 == 4 || i2 == 5) {
                }
                break;
            default:
                if (i2 == 0 || i2 == 1) {
                }
                break;
        }
        return true;
    }
}
