package androidx.appcompat.app;

import android.content.Context;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.os.PowerManager;

/* loaded from: classes.dex */
public final class x extends y {
    public final /* synthetic */ int d = 0;
    public final /* synthetic */ B e;
    public final Object f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(B b, com.google.android.gms.internal.appset.e eVar) {
        super(b);
        this.e = b;
        this.f = eVar;
    }

    @Override // androidx.appcompat.app.y
    public final IntentFilter d() {
        switch (this.d) {
            case 0:
                IntentFilter intentFilter = new IntentFilter();
                intentFilter.addAction("android.os.action.POWER_SAVE_MODE_CHANGED");
                return intentFilter;
            default:
                IntentFilter intentFilter2 = new IntentFilter();
                intentFilter2.addAction("android.intent.action.TIME_SET");
                intentFilter2.addAction("android.intent.action.TIMEZONE_CHANGED");
                intentFilter2.addAction("android.intent.action.TIME_TICK");
                return intentFilter2;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x003c  */
    @Override // androidx.appcompat.app.y
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f() {
        /*
            Method dump skipped, instructions count: 260
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.x.f():int");
    }

    @Override // androidx.appcompat.app.y
    public final void n() throws PackageManager.NameNotFoundException {
        switch (this.d) {
            case 0:
                this.e.m(true, true);
                break;
            default:
                this.e.m(true, true);
                break;
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public x(B b, Context context) {
        super(b);
        this.e = b;
        this.f = (PowerManager) context.getApplicationContext().getSystemService("power");
    }
}
