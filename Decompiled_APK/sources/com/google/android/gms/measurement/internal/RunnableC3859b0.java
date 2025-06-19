package com.google.android.gms.measurement.internal;

import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteException;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.measurement.internal.b0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC3859b0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ zzr b;
    public final /* synthetic */ BinderC3869g0 c;

    public /* synthetic */ RunnableC3859b0(BinderC3869g0 binderC3869g0, zzr zzrVar, int i) {
        this.a = i;
        this.c = binderC3869g0;
        this.b = zzrVar;
    }

    @Override // java.lang.Runnable
    public final void run() throws Throwable {
        switch (this.a) {
            case 0:
                r1 r1Var = this.c.a;
                r1Var.j();
                r1Var.R(this.b);
                break;
            case 1:
                BinderC3869g0 binderC3869g0 = this.c;
                binderC3869g0.a.j();
                r1 r1Var2 = binderC3869g0.a;
                Z.l(r1Var2);
                zzr zzrVar = this.b;
                com.google.android.gms.common.internal.u.h(zzrVar);
                String str = zzrVar.a;
                com.google.android.gms.common.internal.u.e(str);
                int i = 0;
                if (r1Var2.h0().f0(null, AbstractC3893t.y0)) {
                    ((com.google.android.gms.common.util.b) r1Var2.f()).getClass();
                    long jCurrentTimeMillis = System.currentTimeMillis();
                    int iY = r1Var2.h0().Y(null, AbstractC3893t.h0);
                    r1Var2.h0();
                    long jLongValue = jCurrentTimeMillis - ((Long) AbstractC3893t.e.a(null)).longValue();
                    while (i < iY && r1Var2.G(jLongValue, null)) {
                        i++;
                    }
                } else {
                    r1Var2.h0();
                    long jIntValue = ((Integer) AbstractC3893t.l.a(null)).intValue();
                    while (i < jIntValue && r1Var2.G(0L, str)) {
                        i++;
                    }
                }
                if (r1Var2.h0().f0(null, AbstractC3893t.z0)) {
                    r1Var2.i().S();
                    r1Var2.E();
                }
                if (r1Var2.h0().f0(null, AbstractC3893t.Q0)) {
                    int iA = AbstractC1642h.a(zzrVar.G);
                    o1 o1Var = r1Var2.j;
                    o1Var.S();
                    if (((Y) o1Var.b).g.f0(null, AbstractC3893t.P0) && iA == 2 && !o1.V(str)) {
                        T t = o1Var.c.a;
                        r1.L(t);
                        com.google.android.gms.internal.measurement.E0 e0H0 = t.h0(str);
                        if (e0H0 != null && e0H0.G() && !e0H0.u().q().isEmpty()) {
                            r1Var2.c().o.g("[sgtm] Going background, trigger client side upload. appId", str);
                            ((com.google.android.gms.common.util.b) r1Var2.f()).getClass();
                            r1Var2.Y(System.currentTimeMillis(), str);
                            break;
                        }
                    }
                }
                break;
            default:
                BinderC3869g0 binderC3869g02 = this.c;
                binderC3869g02.a.j();
                r1 r1Var3 = binderC3869g02.a;
                if (r1Var3.y != null) {
                    ArrayList arrayList = new ArrayList();
                    r1Var3.z = arrayList;
                    arrayList.addAll(r1Var3.y);
                }
                C3874j c3874j = r1Var3.c;
                r1.L(c3874j);
                Y y = (Y) c3874j.b;
                zzr zzrVar2 = this.b;
                String str2 = zzrVar2.a;
                com.google.android.gms.common.internal.u.h(str2);
                com.google.android.gms.common.internal.u.e(str2);
                c3874j.S();
                c3874j.T();
                try {
                    SQLiteDatabase sQLiteDatabaseO0 = c3874j.O0();
                    String[] strArr = {str2};
                    int iDelete = sQLiteDatabaseO0.delete("apps", "app_id=?", strArr) + sQLiteDatabaseO0.delete("events", "app_id=?", strArr) + sQLiteDatabaseO0.delete("events_snapshot", "app_id=?", strArr) + sQLiteDatabaseO0.delete("user_attributes", "app_id=?", strArr) + sQLiteDatabaseO0.delete("conditional_properties", "app_id=?", strArr) + sQLiteDatabaseO0.delete("raw_events", "app_id=?", strArr) + sQLiteDatabaseO0.delete("raw_events_metadata", "app_id=?", strArr) + sQLiteDatabaseO0.delete("queue", "app_id=?", strArr) + sQLiteDatabaseO0.delete("audience_filter_values", "app_id=?", strArr) + sQLiteDatabaseO0.delete("main_event_params", "app_id=?", strArr) + sQLiteDatabaseO0.delete("default_event_params", "app_id=?", strArr) + sQLiteDatabaseO0.delete("trigger_uris", "app_id=?", strArr) + sQLiteDatabaseO0.delete("upload_queue", "app_id=?", strArr);
                    if (iDelete > 0) {
                        I i2 = y.i;
                        Y.k(i2);
                        i2.o.h("Reset analytics data. app, records", str2, Integer.valueOf(iDelete));
                    }
                } catch (SQLiteException e) {
                    I i3 = y.i;
                    Y.k(i3);
                    i3.g.h("Error resetting analytics data. appId, error", I.a0(str2), e);
                }
                if (zzrVar2.h) {
                    r1Var3.O(zzrVar2);
                    break;
                }
                break;
        }
    }
}
