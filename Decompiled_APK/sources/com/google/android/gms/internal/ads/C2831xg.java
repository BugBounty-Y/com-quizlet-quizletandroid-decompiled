package com.google.android.gms.internal.ads;

import java.util.Collections;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/* renamed from: com.google.android.gms.internal.ads.xg, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2831xg {
    public final Dl a;
    public final C2023eq b;
    public final Lq c;
    public final C2272kf d;
    public final C2280kn e;
    public final Th f;
    public C1849aq g = null;
    public final C2326lq h;
    public final androidx.camera.core.processing.e i;
    public final Xv j;
    public final Ll k;
    public final C2923zm l;

    public C2831xg(Dl dl, C2023eq c2023eq, Lq lq, C2272kf c2272kf, C2280kn c2280kn, Th th, C2326lq c2326lq, androidx.camera.core.processing.e eVar, Xv xv, Ll ll, C2923zm c2923zm) {
        this.a = dl;
        this.b = c2023eq;
        this.c = lq;
        this.d = c2272kf;
        this.e = c2280kn;
        this.f = th;
        this.h = c2326lq;
        this.i = eVar;
        this.j = xv;
        this.k = ll;
        this.l = c2923zm;
    }

    public final Iq a(com.google.common.util.concurrent.e eVar) {
        C2084g6 c2084g6M = this.c.a(eVar, Jq.RENDERER).k(new Ts(this, 16)).m(this.e);
        C2601s7 c2601s7 = AbstractC2773w7.C5;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (!((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            long jIntValue = ((Integer) rVar.c.a(AbstractC2773w7.D5)).intValue();
            TimeUnit timeUnit = TimeUnit.SECONDS;
            c2084g6M = c2084g6M.r(jIntValue);
        }
        return c2084g6M.b();
    }

    /* JADX WARN: Removed duplicated region for block: B:118:0x0272 A[Catch: all -> 0x0103, TRY_LEAVE, TryCatch #3 {all -> 0x0103, blocks: (B:29:0x0098, B:31:0x00b8, B:33:0x00be, B:35:0x00d3, B:37:0x00db, B:45:0x0116, B:47:0x011e, B:49:0x0124, B:53:0x012d, B:64:0x0167, B:56:0x013f, B:63:0x0150, B:66:0x016c, B:42:0x0106, B:67:0x0182, B:74:0x019d, B:77:0x01a5, B:81:0x01c9, B:83:0x01df, B:87:0x0203, B:89:0x0218, B:92:0x022c, B:97:0x023f, B:98:0x0240, B:99:0x024d, B:103:0x0252, B:104:0x0253, B:109:0x0269, B:121:0x0279, B:111:0x026b, B:115:0x026f, B:117:0x0271, B:118:0x0272, B:120:0x0278, B:128:0x028d, B:88:0x020d, B:84:0x01f2, B:80:0x01b3, B:71:0x018c, B:72:0x0191, B:93:0x022d, B:95:0x0237, B:119:0x0273, B:105:0x0254, B:107:0x025e), top: B:161:0x0098, inners: #0, #1, #7, #8 }] */
    /* JADX WARN: Removed duplicated region for block: B:125:0x0281  */
    /* JADX WARN: Removed duplicated region for block: B:131:0x0290  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x0273 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:45:0x0116 A[Catch: all -> 0x0103, TRY_ENTER, TryCatch #3 {all -> 0x0103, blocks: (B:29:0x0098, B:31:0x00b8, B:33:0x00be, B:35:0x00d3, B:37:0x00db, B:45:0x0116, B:47:0x011e, B:49:0x0124, B:53:0x012d, B:64:0x0167, B:56:0x013f, B:63:0x0150, B:66:0x016c, B:42:0x0106, B:67:0x0182, B:74:0x019d, B:77:0x01a5, B:81:0x01c9, B:83:0x01df, B:87:0x0203, B:89:0x0218, B:92:0x022c, B:97:0x023f, B:98:0x0240, B:99:0x024d, B:103:0x0252, B:104:0x0253, B:109:0x0269, B:121:0x0279, B:111:0x026b, B:115:0x026f, B:117:0x0271, B:118:0x0272, B:120:0x0278, B:128:0x028d, B:88:0x020d, B:84:0x01f2, B:80:0x01b3, B:71:0x018c, B:72:0x0191, B:93:0x022d, B:95:0x0237, B:119:0x0273, B:105:0x0254, B:107:0x025e), top: B:161:0x0098, inners: #0, #1, #7, #8 }] */
    /* JADX WARN: Removed duplicated region for block: B:87:0x0203 A[Catch: all -> 0x0103, TryCatch #3 {all -> 0x0103, blocks: (B:29:0x0098, B:31:0x00b8, B:33:0x00be, B:35:0x00d3, B:37:0x00db, B:45:0x0116, B:47:0x011e, B:49:0x0124, B:53:0x012d, B:64:0x0167, B:56:0x013f, B:63:0x0150, B:66:0x016c, B:42:0x0106, B:67:0x0182, B:74:0x019d, B:77:0x01a5, B:81:0x01c9, B:83:0x01df, B:87:0x0203, B:89:0x0218, B:92:0x022c, B:97:0x023f, B:98:0x0240, B:99:0x024d, B:103:0x0252, B:104:0x0253, B:109:0x0269, B:121:0x0279, B:111:0x026b, B:115:0x026f, B:117:0x0271, B:118:0x0272, B:120:0x0278, B:128:0x028d, B:88:0x020d, B:84:0x01f2, B:80:0x01b3, B:71:0x018c, B:72:0x0191, B:93:0x022d, B:95:0x0237, B:119:0x0273, B:105:0x0254, B:107:0x025e), top: B:161:0x0098, inners: #0, #1, #7, #8 }] */
    /* JADX WARN: Removed duplicated region for block: B:88:0x020d A[Catch: all -> 0x0103, TryCatch #3 {all -> 0x0103, blocks: (B:29:0x0098, B:31:0x00b8, B:33:0x00be, B:35:0x00d3, B:37:0x00db, B:45:0x0116, B:47:0x011e, B:49:0x0124, B:53:0x012d, B:64:0x0167, B:56:0x013f, B:63:0x0150, B:66:0x016c, B:42:0x0106, B:67:0x0182, B:74:0x019d, B:77:0x01a5, B:81:0x01c9, B:83:0x01df, B:87:0x0203, B:89:0x0218, B:92:0x022c, B:97:0x023f, B:98:0x0240, B:99:0x024d, B:103:0x0252, B:104:0x0253, B:109:0x0269, B:121:0x0279, B:111:0x026b, B:115:0x026f, B:117:0x0271, B:118:0x0272, B:120:0x0278, B:128:0x028d, B:88:0x020d, B:84:0x01f2, B:80:0x01b3, B:71:0x018c, B:72:0x0191, B:93:0x022d, B:95:0x0237, B:119:0x0273, B:105:0x0254, B:107:0x025e), top: B:161:0x0098, inners: #0, #1, #7, #8 }] */
    /* JADX WARN: Removed duplicated region for block: B:91:0x022a A[ADDED_TO_REGION] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.Iq b() {
        /*
            Method dump skipped, instructions count: 791
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2831xg.b():com.google.android.gms.internal.ads.Iq");
    }

    public final Iq c(com.google.common.util.concurrent.e eVar) {
        C1849aq c1849aq = this.g;
        if (c1849aq != null) {
            return new C2084g6(this.c, Jq.SERVER_TRANSACTION, null, Lq.d, Collections.EMPTY_LIST, AbstractC2025es.E(c1849aq)).b();
        }
        C2084g6 c2084g6 = com.google.android.gms.ads.internal.j.C.j;
        c2084g6.getClass();
        C2601s7 c2601s7 = AbstractC2773w7.o4;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        if (((Boolean) rVar.c.a(c2601s7)).booleanValue()) {
            synchronized (c2084g6.c) {
                try {
                    c2084g6.v();
                    ScheduledFuture scheduledFuture = (ScheduledFuture) c2084g6.a;
                    if (scheduledFuture != null) {
                        scheduledFuture.cancel(false);
                    }
                    c2084g6.a = AbstractC2270kd.d.schedule((RunnableC1989e) c2084g6.b, ((Long) rVar.c.a(AbstractC2773w7.p4)).longValue(), TimeUnit.MILLISECONDS);
                } finally {
                }
            }
        }
        return this.c.a(eVar, Jq.SERVER_TRANSACTION).m(new D9(this.k, 4)).b();
    }
}
