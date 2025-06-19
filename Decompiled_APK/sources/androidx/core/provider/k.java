package androidx.core.provider;

import android.os.RemoteException;
import com.google.android.gms.internal.measurement.L;
import com.google.android.gms.internal.mlkit_vision_camera.f3;
import com.google.android.gms.internal.mlkit_vision_common.K4;
import com.google.android.gms.measurement.internal.D0;
import com.google.android.gms.measurement.internal.EnumC3879l0;
import com.google.android.gms.measurement.internal.I;
import com.google.android.gms.measurement.internal.InterfaceC3897v;
import com.google.android.gms.measurement.internal.O;
import com.google.android.gms.measurement.internal.Y;
import com.google.android.gms.measurement.internal.Y0;
import com.google.android.gms.measurement.internal.x1;
import com.google.android.gms.measurement.internal.zzr;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.z;

/* loaded from: classes.dex */
public final class k implements Runnable {
    public final /* synthetic */ int a;
    public Object b;
    public Object c;
    public Object d;

    public /* synthetic */ k() {
        this.a = 0;
    }

    private final void a() {
        boolean zK;
        O o;
        I i;
        L l = (L) this.c;
        Y0 y0 = (Y0) this.d;
        Y y = (Y) y0.b;
        String strU2 = null;
        try {
            try {
                O o2 = y.h;
                Y.h(o2);
                zK = o2.Z().k(EnumC3879l0.ANALYTICS_STORAGE);
                o = y.h;
                i = y.i;
            } catch (RemoteException e) {
                I i2 = y.i;
                Y.k(i2);
                i2.g.g("Failed to get app instance id", e);
            }
            if (zK) {
                InterfaceC3897v interfaceC3897v = y0.e;
                if (interfaceC3897v != null) {
                    strU2 = interfaceC3897v.u2((zzr) this.b);
                    if (strU2 != null) {
                        D0 d0 = y.p;
                        Y.j(d0);
                        d0.h.set(strU2);
                        Y.h(o);
                        o.i.m(strU2);
                    }
                    y0.h0();
                    x1 x1Var = y.l;
                    Y.h(x1Var);
                    x1Var.t0(strU2, l);
                    return;
                }
                Y.k(i);
                i.g.f("Failed to get app instance id");
            } else {
                Y.k(i);
                i.l.f("Analytics storage consent denied; will not get app instance id");
                D0 d02 = y.p;
                Y.j(d02);
                d02.h.set(null);
                Y.h(o);
                o.i.m(null);
            }
            x1 x1Var2 = y.l;
            Y.h(x1Var2);
            x1Var2.t0(null, l);
        } catch (Throwable th) {
            x1 x1Var3 = y.l;
            Y.h(x1Var3);
            x1Var3.t0(null, l);
            throw th;
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:166:0x048c  */
    /* JADX WARN: Removed duplicated region for block: B:169:0x0492  */
    /* JADX WARN: Removed duplicated region for block: B:170:0x04a3  */
    /* JADX WARN: Removed duplicated region for block: B:202:0x05be  */
    /* JADX WARN: Removed duplicated region for block: B:210:0x05ea  */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 2552
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.core.provider.k.run():void");
    }

    public /* synthetic */ k(int i, Object obj, Object obj2, Object obj3, boolean z) {
        this.a = i;
        this.b = obj2;
        this.c = obj3;
        this.d = obj;
    }

    public /* synthetic */ k(f3 f3Var, com.quizlet.data.repository.explanations.myexplanations.a aVar, String str) {
        this.a = 11;
        this.b = f3Var;
        this.d = aVar;
        this.c = str;
    }

    public /* synthetic */ k(K4 k4, com.quizlet.data.repository.qclass.c cVar, String str) {
        this.a = 12;
        this.b = k4;
        this.c = cVar;
        this.d = str;
    }

    public /* synthetic */ k(Object obj, Object obj2, Object obj3, int i) {
        this.a = i;
        this.b = obj;
        this.c = obj2;
        this.d = obj3;
    }

    public k(z history) {
        this.a = 25;
        Intrinsics.checkNotNullParameter(history, "history");
        this.b = history;
        this.c = "";
    }
}
