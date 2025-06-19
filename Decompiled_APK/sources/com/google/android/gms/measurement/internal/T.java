package com.google.android.gms.measurement.internal;

import android.text.TextUtils;
import androidx.collection.C0208f;
import com.google.android.gms.internal.ads.C1719Ka;
import com.google.android.gms.internal.measurement.C3005i2;
import com.google.android.gms.internal.measurement.C3029n1;
import com.google.android.gms.internal.measurement.C3034o1;
import com.google.android.gms.internal.measurement.C3072w0;
import com.google.android.gms.internal.measurement.C3087z0;
import com.google.android.gms.internal.measurement.zzd;
import com.google.android.gms.internal.measurement.zzmm;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/* loaded from: classes2.dex */
public final class T extends m1 implements InterfaceC3862d {
    public final C0208f e;
    public final C0208f f;
    public final C0208f g;
    public final C0208f h;
    public final C0208f i;
    public final C0208f j;
    public final S k;
    public final com.google.android.gms.internal.instantapps.a l;
    public final C0208f m;
    public final C0208f n;
    public final C0208f o;

    public T(r1 r1Var) {
        super(r1Var);
        this.e = new C0208f(0);
        this.f = new C0208f(0);
        this.g = new C0208f(0);
        this.h = new C0208f(0);
        this.i = new C0208f(0);
        this.m = new C0208f(0);
        this.n = new C0208f(0);
        this.o = new C0208f(0);
        this.j = new C0208f(0);
        this.k = new S(this);
        this.l = new com.google.android.gms.internal.instantapps.a(this, 27);
    }

    public static final C0208f c0(com.google.android.gms.internal.measurement.E0 e0) {
        C0208f c0208f = new C0208f(0);
        for (com.google.android.gms.internal.measurement.I0 i0 : e0.A()) {
            c0208f.put(i0.n(), i0.o());
        }
        return c0208f;
    }

    public static final EnumC3879l0 d0(int i) {
        int i2 = i - 1;
        if (i2 == 1) {
            return EnumC3879l0.AD_STORAGE;
        }
        if (i2 == 2) {
            return EnumC3879l0.ANALYTICS_STORAGE;
        }
        if (i2 == 3) {
            return EnumC3879l0.AD_USER_DATA;
        }
        if (i2 != 4) {
            return null;
        }
        return EnumC3879l0.AD_PERSONALIZATION;
    }

    @Override // com.google.android.gms.measurement.internal.m1
    public final void V() {
    }

    public final boolean W(String str) {
        S();
        a0(str);
        C0208f c0208f = this.f;
        return c0208f.get(str) != null && ((Set) c0208f.get(str)).contains("app_instance_id");
    }

    public final boolean X(String str) {
        S();
        a0(str);
        C0208f c0208f = this.f;
        if (c0208f.get(str) != null) {
            return ((Set) c0208f.get(str)).contains("os_version") || ((Set) c0208f.get(str)).contains("device_info");
        }
        return false;
    }

    public final com.google.android.gms.internal.measurement.E0 Y(String str, byte[] bArr) {
        Y y = (Y) this.b;
        if (bArr == null) {
            return com.google.android.gms.internal.measurement.E0.t();
        }
        try {
            com.google.android.gms.internal.measurement.E0 e0 = (com.google.android.gms.internal.measurement.E0) ((com.google.android.gms.internal.measurement.D0) M.y0(com.google.android.gms.internal.measurement.E0.s(), bArr)).f();
            I i = y.i;
            Y.k(i);
            i.o.h("Parsed config. version, gmp_app_id", e0.H() ? Long.valueOf(e0.p()) : null, e0.F() ? e0.v() : null);
            return e0;
        } catch (zzmm e) {
            I i2 = y.i;
            Y.k(i2);
            i2.j.h("Unable to merge remote config. appId", I.a0(str), e);
            return com.google.android.gms.internal.measurement.E0.t();
        } catch (RuntimeException e2) {
            I i3 = y.i;
            Y.k(i3);
            i3.j.h("Unable to merge remote config. appId", I.a0(str), e2);
            return com.google.android.gms.internal.measurement.E0.t();
        }
    }

    public final void Z(String str, com.google.android.gms.internal.measurement.D0 d0) {
        HashSet hashSet = new HashSet();
        C0208f c0208f = new C0208f(0);
        C0208f c0208f2 = new C0208f(0);
        C0208f c0208f3 = new C0208f(0);
        Iterator it2 = Collections.unmodifiableList(((com.google.android.gms.internal.measurement.E0) d0.b).y()).iterator();
        while (it2.hasNext()) {
            hashSet.add(((com.google.android.gms.internal.measurement.A0) it2.next()).n());
        }
        for (int i = 0; i < ((com.google.android.gms.internal.measurement.E0) d0.b).o(); i++) {
            com.google.android.gms.internal.measurement.B0 b0 = (com.google.android.gms.internal.measurement.B0) ((com.google.android.gms.internal.measurement.E0) d0.b).r(i).f();
            boolean zIsEmpty = b0.i().isEmpty();
            Y y = (Y) this.b;
            if (zIsEmpty) {
                I i2 = y.i;
                Y.k(i2);
                i2.j.f("EventConfig contained null event name");
            } else {
                String strI = b0.i();
                String strD = AbstractC3883n0.d(b0.i(), AbstractC3883n0.a, AbstractC3883n0.c);
                if (!TextUtils.isEmpty(strD)) {
                    b0.h();
                    com.google.android.gms.internal.measurement.C0.p((com.google.android.gms.internal.measurement.C0) b0.b, strD);
                    d0.h();
                    com.google.android.gms.internal.measurement.E0.D((com.google.android.gms.internal.measurement.E0) d0.b, i, (com.google.android.gms.internal.measurement.C0) b0.f());
                }
                if (((com.google.android.gms.internal.measurement.C0) b0.b).s() && ((com.google.android.gms.internal.measurement.C0) b0.b).q()) {
                    c0208f.put(strI, Boolean.TRUE);
                }
                if (((com.google.android.gms.internal.measurement.C0) b0.b).t() && ((com.google.android.gms.internal.measurement.C0) b0.b).r()) {
                    c0208f2.put(b0.i(), Boolean.TRUE);
                }
                if (((com.google.android.gms.internal.measurement.C0) b0.b).u()) {
                    if (((com.google.android.gms.internal.measurement.C0) b0.b).n() < 2 || ((com.google.android.gms.internal.measurement.C0) b0.b).n() > 65535) {
                        I i3 = y.i;
                        Y.k(i3);
                        i3.j.h("Invalid sampling rate. Event name, sample rate", b0.i(), Integer.valueOf(((com.google.android.gms.internal.measurement.C0) b0.b).n()));
                    } else {
                        c0208f3.put(b0.i(), Integer.valueOf(((com.google.android.gms.internal.measurement.C0) b0.b).n()));
                    }
                }
            }
        }
        this.f.put(str, hashSet);
        this.g.put(str, c0208f);
        this.h.put(str, c0208f2);
        this.j.put(str, c0208f3);
    }

    public final void a0(String str) {
        T();
        S();
        com.google.android.gms.common.internal.u.e(str);
        C0208f c0208f = this.i;
        if (c0208f.get(str) == null) {
            C3874j c3874j = this.c.c;
            r1.L(c3874j);
            com.quizlet.data.repository.user.a aVarR0 = c3874j.R0(str);
            C0208f c0208f2 = this.o;
            C0208f c0208f3 = this.n;
            C0208f c0208f4 = this.m;
            C0208f c0208f5 = this.e;
            if (aVarR0 != null) {
                com.google.android.gms.internal.measurement.D0 d0 = (com.google.android.gms.internal.measurement.D0) Y(str, (byte[]) aVarR0.b).f();
                Z(str, d0);
                c0208f5.put(str, c0((com.google.android.gms.internal.measurement.E0) d0.f()));
                c0208f.put(str, (com.google.android.gms.internal.measurement.E0) d0.f());
                b0(str, (com.google.android.gms.internal.measurement.E0) d0.f());
                c0208f4.put(str, ((com.google.android.gms.internal.measurement.E0) d0.b).w());
                c0208f3.put(str, (String) aVarR0.c);
                c0208f2.put(str, (String) aVarR0.d);
                return;
            }
            c0208f5.put(str, null);
            this.g.put(str, null);
            this.f.put(str, null);
            this.h.put(str, null);
            c0208f.put(str, null);
            c0208f4.put(str, null);
            c0208f3.put(str, null);
            c0208f2.put(str, null);
            this.j.put(str, null);
        }
    }

    public final void b0(String str, com.google.android.gms.internal.measurement.E0 e0) {
        int iN = e0.n();
        S s = this.k;
        if (iN == 0) {
            s.l(str);
            return;
        }
        Y y = (Y) this.b;
        I i = y.i;
        Y.k(i);
        i.o.g("EES programs found", Integer.valueOf(e0.n()));
        C3034o1 c3034o1 = (C3034o1) e0.z().get(0);
        try {
            com.google.android.gms.internal.measurement.D d = new com.google.android.gms.internal.measurement.D();
            androidx.work.impl.model.n nVar = d.a;
            ((HashMap) ((C3005i2) nVar.d).a).put("internal.remoteConfig", new Q(this, str, 0));
            ((HashMap) ((C3005i2) nVar.d).a).put("internal.appMetadata", new Q(this, str, 1));
            ((HashMap) ((C3005i2) nVar.d).a).put("internal.logger", new androidx.camera.core.impl.utils.executor.c(this, 13));
            d.a(c3034o1);
            s.k(str, d);
            Y.k(i);
            C1719Ka c1719Ka = i.o;
            c1719Ka.h("EES program loaded for appId, activities", str, Integer.valueOf(c3034o1.n().n()));
            for (C3029n1 c3029n1 : c3034o1.n().p()) {
                Y.k(i);
                c1719Ka.g("EES program activity", c3029n1.n());
            }
        } catch (zzd unused) {
            I i2 = y.i;
            Y.k(i2);
            i2.g.g("Failed to load EES program. appId", str);
        }
    }

    public final int e0(String str, String str2) {
        Integer num;
        S();
        a0(str);
        Map map = (Map) this.j.get(str);
        if (map == null || (num = (Integer) map.get(str2)) == null) {
            return 1;
        }
        return num.intValue();
    }

    public final EnumC3875j0 f0(String str, EnumC3879l0 enumC3879l0) {
        S();
        a0(str);
        C3087z0 c3087z0G0 = g0(str);
        EnumC3875j0 enumC3875j0 = EnumC3875j0.UNINITIALIZED;
        if (c3087z0G0 != null) {
            Iterator it2 = c3087z0G0.r().iterator();
            while (true) {
                if (!it2.hasNext()) {
                    break;
                }
                C3072w0 c3072w0 = (C3072w0) it2.next();
                if (d0(c3072w0.o()) == enumC3879l0) {
                    int iN = c3072w0.n() - 1;
                    if (iN == 1) {
                        return EnumC3875j0.GRANTED;
                    }
                    if (iN == 2) {
                        return EnumC3875j0.DENIED;
                    }
                }
            }
        }
        return enumC3875j0;
    }

    @Override // com.google.android.gms.measurement.internal.InterfaceC3862d
    public final String g(String str, String str2) {
        S();
        a0(str);
        Map map = (Map) this.e.get(str);
        if (map != null) {
            return (String) map.get(str2);
        }
        return null;
    }

    public final C3087z0 g0(String str) {
        S();
        a0(str);
        com.google.android.gms.internal.measurement.E0 e0H0 = h0(str);
        if (e0H0 == null || !e0H0.E()) {
            return null;
        }
        return e0H0.q();
    }

    public final com.google.android.gms.internal.measurement.E0 h0(String str) {
        T();
        S();
        com.google.android.gms.common.internal.u.e(str);
        a0(str);
        return (com.google.android.gms.internal.measurement.E0) this.i.get(str);
    }

    public final String i0(String str) {
        S();
        a0(str);
        return (String) this.m.get(str);
    }

    public final boolean j0(String str, EnumC3879l0 enumC3879l0) {
        S();
        a0(str);
        C3087z0 c3087z0G0 = g0(str);
        if (c3087z0G0 == null) {
            return false;
        }
        for (C3072w0 c3072w0 : c3087z0G0.p()) {
            if (enumC3879l0 == d0(c3072w0.o())) {
                return c3072w0.n() == 2;
            }
        }
        return false;
    }

    public final boolean k0(String str, String str2) {
        Boolean bool;
        S();
        a0(str);
        if ("ecommerce_purchase".equals(str2) || "purchase".equals(str2) || "refund".equals(str2)) {
            return true;
        }
        Map map = (Map) this.h.get(str);
        if (map == null || (bool = (Boolean) map.get(str2)) == null) {
            return false;
        }
        return bool.booleanValue();
    }

    public final boolean l0(String str, String str2) {
        Boolean bool;
        S();
        a0(str);
        if ("1".equals(g(str, "measurement.upload.blacklist_internal")) && x1.L0(str2)) {
            return true;
        }
        if ("1".equals(g(str, "measurement.upload.blacklist_public")) && x1.M0(str2)) {
            return true;
        }
        Map map = (Map) this.g.get(str);
        if (map == null || (bool = (Boolean) map.get(str2)) == null) {
            return false;
        }
        return bool.booleanValue();
    }

    /* JADX WARN: Code restructure failed: missing block: B:100:0x0405, code lost:
    
        r6.put(r0, r3);
        r28 = r0;
        r6.put("property_name", r8.q());
     */
    /* JADX WARN: Code restructure failed: missing block: B:101:0x0417, code lost:
    
        if (r8.w() == false) goto L103;
     */
    /* JADX WARN: Code restructure failed: missing block: B:102:0x0419, code lost:
    
        r0 = java.lang.Boolean.valueOf(r8.u());
     */
    /* JADX WARN: Code restructure failed: missing block: B:103:0x0422, code lost:
    
        r0 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:104:0x0423, code lost:
    
        r6.put("session_scoped", r0);
        r6.put("data", r9);
     */
    /* JADX WARN: Code restructure failed: missing block: B:106:0x0435, code lost:
    
        if (r10.O0().insertWithOnConflict("property_filters", null, r6, 5) != (-1)) goto L111;
     */
    /* JADX WARN: Code restructure failed: missing block: B:107:0x0437, code lost:
    
        r0 = r5.i;
        com.google.android.gms.measurement.internal.Y.k(r0);
        r0.g.g("Failed to insert property filter (got -1). appId", com.google.android.gms.measurement.internal.I.a0(r32));
     */
    /* JADX WARN: Code restructure failed: missing block: B:109:0x0448, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:111:0x044a, code lost:
    
        r6 = r23;
        r3 = r27;
        r0 = r28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:112:0x0452, code lost:
    
        r1 = r5.i;
        com.google.android.gms.measurement.internal.Y.k(r1);
        r1.g.h("Error storing property filter. appId", com.google.android.gms.measurement.internal.I.a0(r32), r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:113:0x0462, code lost:
    
        r10.T();
        r10.S();
        com.google.android.gms.common.internal.u.e(r32);
        r0 = r10.O0();
        r0.delete("property_filters", "app_id=? and audience_id=?", new java.lang.String[]{r32, java.lang.String.valueOf(r26)});
        r0.delete("event_filters", "app_id=? and audience_id=?", new java.lang.String[]{r32, java.lang.String.valueOf(r26)});
     */
    /* JADX WARN: Code restructure failed: missing block: B:114:0x0485, code lost:
    
        r1 = r24;
        r3 = r25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0267, code lost:
    
        r8 = r0.t().iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x0273, code lost:
    
        if (r8.hasNext() == false) goto L188;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x027f, code lost:
    
        if (((com.google.android.gms.internal.measurement.C3062u0) r8.next()).v() != false) goto L196;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0281, code lost:
    
        r0 = r5.i;
        com.google.android.gms.measurement.internal.Y.k(r0);
        r0.j.h("Property filter with no ID. Audience definition ignored. appId, audienceId", com.google.android.gms.measurement.internal.I.a0(r32), java.lang.Integer.valueOf(r6));
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x0297, code lost:
    
        r8 = r0.s().iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x02a3, code lost:
    
        r23 = r0;
        r0 = "filter_id";
        r24 = r1;
        r25 = r3;
        r3 = "app_id";
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x02b5, code lost:
    
        if (r8.hasNext() == false) goto L197;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x02b7, code lost:
    
        r9 = (com.google.android.gms.internal.measurement.C3028n0) r8.next();
        r10.T();
        r10.S();
        com.google.android.gms.common.internal.u.e(r32);
        com.google.android.gms.common.internal.u.h(r9);
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x02d1, code lost:
    
        if (r9.s().isEmpty() == false) goto L71;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x02d3, code lost:
    
        r0 = r5.i;
        com.google.android.gms.measurement.internal.Y.k(r0);
        r0 = r0.j;
        r3 = com.google.android.gms.measurement.internal.I.a0(r32);
        r4 = java.lang.Integer.valueOf(r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x02e8, code lost:
    
        if (r9.A() == false) goto L69;
     */
    /* JADX WARN: Code restructure failed: missing block: B:66:0x02ea, code lost:
    
        r5 = java.lang.Integer.valueOf(r9.o());
     */
    /* JADX WARN: Code restructure failed: missing block: B:69:0x02f6, code lost:
    
        r5 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:70:0x02f7, code lost:
    
        r0.i("Event filter had no event name. Audience definition ignored. appId, audienceId, filterId", r3, r4, java.lang.String.valueOf(r5));
        r26 = r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:71:0x0302, code lost:
    
        r26 = r6;
        r6 = r9.c();
        r27 = r8;
        r8 = new android.content.ContentValues();
        r8.put("app_id", r32);
        r8.put("audience_id", java.lang.Integer.valueOf(r26));
     */
    /* JADX WARN: Code restructure failed: missing block: B:72:0x031d, code lost:
    
        if (r9.A() == false) goto L74;
     */
    /* JADX WARN: Code restructure failed: missing block: B:73:0x031f, code lost:
    
        r1 = java.lang.Integer.valueOf(r9.o());
     */
    /* JADX WARN: Code restructure failed: missing block: B:74:0x0328, code lost:
    
        r1 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:75:0x0329, code lost:
    
        r8.put("filter_id", r1);
        r8.put("event_name", r9.s());
     */
    /* JADX WARN: Code restructure failed: missing block: B:76:0x0339, code lost:
    
        if (r9.B() == false) goto L78;
     */
    /* JADX WARN: Code restructure failed: missing block: B:77:0x033b, code lost:
    
        r0 = java.lang.Boolean.valueOf(r9.y());
     */
    /* JADX WARN: Code restructure failed: missing block: B:78:0x0344, code lost:
    
        r0 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:79:0x0345, code lost:
    
        r8.put("session_scoped", r0);
        r8.put("data", r6);
     */
    /* JADX WARN: Code restructure failed: missing block: B:81:0x0357, code lost:
    
        if (r10.O0().insertWithOnConflict("event_filters", null, r8, 5) != (-1)) goto L200;
     */
    /* JADX WARN: Code restructure failed: missing block: B:82:0x0359, code lost:
    
        r0 = r5.i;
        com.google.android.gms.measurement.internal.Y.k(r0);
        r0.g.g("Failed to insert event filter (got -1). appId", com.google.android.gms.measurement.internal.I.a0(r32));
     */
    /* JADX WARN: Code restructure failed: missing block: B:83:0x0369, code lost:
    
        r0 = r23;
        r1 = r24;
        r3 = r25;
        r6 = r26;
        r8 = r27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:84:0x0375, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x0376, code lost:
    
        r1 = r5.i;
        com.google.android.gms.measurement.internal.Y.k(r1);
        r1.g.h("Error storing event filter. appId", com.google.android.gms.measurement.internal.I.a0(r32), r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x0388, code lost:
    
        r26 = r6;
        r6 = r23.t().iterator();
     */
    /* JADX WARN: Code restructure failed: missing block: B:88:0x0396, code lost:
    
        if (r6.hasNext() == false) goto L202;
     */
    /* JADX WARN: Code restructure failed: missing block: B:89:0x0398, code lost:
    
        r8 = (com.google.android.gms.internal.measurement.C3062u0) r6.next();
        r10.T();
        r10.S();
        com.google.android.gms.common.internal.u.e(r32);
        com.google.android.gms.common.internal.u.h(r8);
     */
    /* JADX WARN: Code restructure failed: missing block: B:90:0x03b2, code lost:
    
        if (r8.q().isEmpty() == false) goto L96;
     */
    /* JADX WARN: Code restructure failed: missing block: B:91:0x03b4, code lost:
    
        r0 = r5.i;
        com.google.android.gms.measurement.internal.Y.k(r0);
        r0 = r0.j;
        r3 = com.google.android.gms.measurement.internal.I.a0(r32);
        r4 = java.lang.Integer.valueOf(r26);
     */
    /* JADX WARN: Code restructure failed: missing block: B:92:0x03c9, code lost:
    
        if (r8.v() == false) goto L94;
     */
    /* JADX WARN: Code restructure failed: missing block: B:93:0x03cb, code lost:
    
        r5 = java.lang.Integer.valueOf(r8.n());
     */
    /* JADX WARN: Code restructure failed: missing block: B:94:0x03d4, code lost:
    
        r5 = null;
     */
    /* JADX WARN: Code restructure failed: missing block: B:95:0x03d5, code lost:
    
        r0.i("Property filter had no property name. Audience definition ignored. appId, audienceId, filterId", r3, r4, java.lang.String.valueOf(r5));
     */
    /* JADX WARN: Code restructure failed: missing block: B:96:0x03de, code lost:
    
        r9 = r8.c();
        r23 = r6;
        r6 = new android.content.ContentValues();
        r6.put(r3, r32);
        r27 = r3;
        r6.put("audience_id", java.lang.Integer.valueOf(r26));
     */
    /* JADX WARN: Code restructure failed: missing block: B:97:0x03f9, code lost:
    
        if (r8.v() == false) goto L99;
     */
    /* JADX WARN: Code restructure failed: missing block: B:98:0x03fb, code lost:
    
        r3 = java.lang.Integer.valueOf(r8.n());
     */
    /* JADX WARN: Code restructure failed: missing block: B:99:0x0404, code lost:
    
        r3 = null;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void m0(java.lang.String r32, java.lang.String r33, java.lang.String r34, byte[] r35) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 1558
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.T.m0(java.lang.String, java.lang.String, java.lang.String, byte[]):void");
    }
}
