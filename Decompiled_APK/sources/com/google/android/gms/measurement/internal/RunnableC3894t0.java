package com.google.android.gms.measurement.internal;

import android.os.Bundle;
import java.util.Iterator;
import java.util.TreeSet;
import org.json.JSONException;

/* renamed from: com.google.android.gms.measurement.internal.t0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final /* synthetic */ class RunnableC3894t0 implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Bundle b;
    public final /* synthetic */ D0 c;

    public /* synthetic */ RunnableC3894t0(D0 d0, Bundle bundle, int i) {
        this.a = i;
        this.c = d0;
        this.b = bundle;
    }

    @Override // java.lang.Runnable
    public final void run() throws JSONException {
        Bundle bundle;
        switch (this.a) {
            case 0:
                Bundle bundle2 = this.b;
                boolean zIsEmpty = bundle2.isEmpty();
                D0 d0 = this.c;
                if (zIsEmpty) {
                    bundle = bundle2;
                } else {
                    Y y = (Y) d0.b;
                    O o = y.h;
                    Y.h(o);
                    bundle = new Bundle(o.A.h());
                    Iterator<String> it2 = bundle2.keySet().iterator();
                    while (true) {
                        boolean zHasNext = it2.hasNext();
                        com.quizlet.data.repository.school.membership.a aVar = d0.x;
                        C3864e c3864e = y.g;
                        I i = y.i;
                        x1 x1Var = y.l;
                        if (zHasNext) {
                            String next = it2.next();
                            Object obj = bundle2.get(next);
                            if (obj != null && !(obj instanceof String) && !(obj instanceof Long) && !(obj instanceof Double)) {
                                Y.h(x1Var);
                                if (x1.I0(obj)) {
                                    x1.l0(aVar, null, 27, null, null, 0);
                                }
                                Y.k(i);
                                i.l.h("Invalid default event parameter type. Name, value", next, obj);
                            } else if (x1.L0(next)) {
                                Y.k(i);
                                i.l.g("Invalid default event parameter name. Name", next);
                            } else if (obj == null) {
                                bundle.remove(next);
                            } else {
                                Y.h(x1Var);
                                c3864e.getClass();
                                if (x1Var.D0("param", next, com.pubmatic.sdk.video.a.GENERAL_NONLINEAR_AD_ERROR, obj)) {
                                    x1Var.m0(bundle, next, obj);
                                }
                            }
                        } else {
                            Y.h(x1Var);
                            x1 x1Var2 = ((Y) c3864e.b).l;
                            Y.h(x1Var2);
                            int i2 = x1Var2.K0(201500000) ? 100 : 25;
                            if (bundle.size() > i2) {
                                Iterator it3 = new TreeSet(bundle.keySet()).iterator();
                                int i3 = 0;
                                while (it3.hasNext()) {
                                    String str = (String) it3.next();
                                    i3++;
                                    if (i3 > i2) {
                                        bundle.remove(str);
                                    }
                                }
                                Y.h(x1Var);
                                x1.l0(aVar, null, 26, null, null, 0);
                                Y.k(i);
                                i.l.f("Too many default event parameters set. Discarding beyond event parameter limit");
                            }
                        }
                    }
                }
                Y y2 = (Y) d0.b;
                O o2 = y2.h;
                Y.h(o2);
                o2.A.i(bundle);
                if (bundle2.isEmpty()) {
                    if (!y2.g.f0(null, AbstractC3893t.d1)) {
                    }
                }
                ((Y) d0.b).r().a0(bundle);
                break;
            default:
                D0 d02 = this.c;
                d02.S();
                d02.Q();
                Bundle bundle3 = this.b;
                String string = bundle3.getString("name");
                String string2 = bundle3.getString("origin");
                com.google.android.gms.common.internal.u.e(string);
                com.google.android.gms.common.internal.u.e(string2);
                com.google.android.gms.common.internal.u.h(bundle3.get("value"));
                Y y3 = (Y) d02.b;
                if (!y3.a()) {
                    I i4 = y3.i;
                    Y.k(i4);
                    i4.o.f("Conditional property not set since app measurement is disabled");
                    break;
                } else {
                    zzqb zzqbVar = new zzqb(bundle3.getLong("triggered_timestamp"), bundle3.get("value"), string, string2);
                    try {
                        x1 x1Var3 = y3.l;
                        Y.h(x1Var3);
                        bundle3.getString("app_id");
                        zzbh zzbhVarX = x1Var3.X(bundle3.getString("triggered_event_name"), bundle3.getBundle("triggered_event_params"), string2, 0L, true);
                        Y.h(x1Var3);
                        bundle3.getString("app_id");
                        zzbh zzbhVarX2 = x1Var3.X(bundle3.getString("timed_out_event_name"), bundle3.getBundle("timed_out_event_params"), string2, 0L, true);
                        bundle3.getString("app_id");
                        y3.r().Z(new zzai(bundle3.getString("app_id"), string2, zzqbVar, bundle3.getLong("creation_timestamp"), false, bundle3.getString("trigger_event_name"), zzbhVarX2, bundle3.getLong("trigger_timeout"), zzbhVarX, bundle3.getLong("time_to_live"), x1Var3.X(bundle3.getString("expired_event_name"), bundle3.getBundle("expired_event_params"), string2, 0L, true)));
                        break;
                    } catch (IllegalArgumentException unused) {
                        return;
                    }
                }
        }
    }
}
