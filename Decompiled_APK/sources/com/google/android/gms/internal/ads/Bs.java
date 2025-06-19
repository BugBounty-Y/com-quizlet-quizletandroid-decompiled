package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.SharedPreferences;
import android.database.SQLException;
import android.database.sqlite.SQLiteDatabase;
import android.provider.Settings;
import android.telephony.TelephonyManager;
import android.util.SparseArray;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class Bs implements Gq, InterfaceC2491pj {
    public static final Object f = new Object();
    public final boolean a;
    public final Object b;
    public final Object c;
    public final Object d;
    public final Object e;

    public /* synthetic */ Bs(androidx.appcompat.app.K k, boolean z, ArrayList arrayList, C2686u6 c2686u6, EnumC2901z6 enumC2901z6) {
        this.b = k;
        this.a = z;
        this.c = arrayList;
        this.d = c2686u6;
        this.e = enumC2901z6;
    }

    public static Bs a(Ir ir, Kr kr, Mr mr, Mr mr2, boolean z) {
        if (mr == Mr.NONE) {
            throw new IllegalArgumentException("Impression owner is none");
        }
        Ir ir2 = Ir.DEFINED_BY_JAVASCRIPT;
        Mr mr3 = Mr.NATIVE;
        if (ir == ir2 && mr == mr3) {
            throw new IllegalArgumentException("ImpressionType/CreativeType can only be defined as DEFINED_BY_JAVASCRIPT if Impression Owner is JavaScript");
        }
        if (kr == Kr.DEFINED_BY_JAVASCRIPT && mr == mr3) {
            throw new IllegalArgumentException("ImpressionType/CreativeType can only be defined as DEFINED_BY_JAVASCRIPT if Impression Owner is JavaScript");
        }
        return new Bs(ir, kr, mr, mr2, z);
    }

    public static String f(C2642t5 c2642t5) {
        C2685u5 c2685u5Z = C2728v5.z();
        String strE = c2642t5.x().E();
        c2685u5Z.e();
        C2728v5.J((C2728v5) c2685u5Z.b, strE);
        String strD = c2642t5.x().D();
        c2685u5Z.e();
        C2728v5.F((C2728v5) c2685u5Z.b, strD);
        long jW = c2642t5.x().w();
        c2685u5Z.e();
        C2728v5.G((C2728v5) c2685u5Z.b, jW);
        long jY = c2642t5.x().y();
        c2685u5Z.e();
        C2728v5.I((C2728v5) c2685u5Z.b, jY);
        long jX = c2642t5.x().x();
        c2685u5Z.e();
        C2728v5.H((C2728v5) c2685u5Z.b, jX);
        return com.google.android.gms.common.util.c.b(((C2728v5) c2685u5Z.c()).d());
    }

    @Override // com.google.android.gms.internal.ads.Gq
    public Object b(Object obj) throws SQLException {
        long j;
        long j2;
        int i;
        C1976dm c1976dm = (C1976dm) ((androidx.appcompat.app.K) this.b).b;
        SQLiteDatabase sQLiteDatabase = (SQLiteDatabase) obj;
        if (((com.google.android.gms.ads.internal.util.C) c1976dm.b).k()) {
            return null;
        }
        EnumC2901z6 enumC2901z6 = (EnumC2901z6) this.e;
        C2686u6 c2686u6 = (C2686u6) this.d;
        ArrayList arrayList = (ArrayList) this.c;
        boolean z = this.a;
        SparseArray sparseArray = C1976dm.i;
        C2772w6 c2772w6L = C2815x6.L();
        c2772w6L.e();
        C2815x6.w((C2815x6) c2772w6L.b, arrayList);
        Context context = c1976dm.d;
        int i2 = Settings.Global.getInt(context.getContentResolver(), "airplane_mode_on", 0) != 0 ? 2 : 1;
        c2772w6L.e();
        C2815x6.x((C2815x6) c2772w6L.b, i2);
        TelephonyManager telephonyManager = c1976dm.f;
        com.google.android.gms.ads.internal.j jVar = com.google.android.gms.ads.internal.j.C;
        jVar.f.getClass();
        int i3 = (com.google.android.gms.ads.internal.util.F.b(context, "android.permission.ACCESS_NETWORK_STATE") && telephonyManager.isDataEnabled()) ? 2 : 1;
        c2772w6L.e();
        C2815x6.y((C2815x6) c2772w6L.b, i3);
        C1889bm c1889bm = c1976dm.g;
        synchronized (c1889bm.h) {
            j = c1889bm.c;
        }
        c2772w6L.e();
        C2815x6.E((C2815x6) c2772w6L.b, j);
        synchronized (c1889bm) {
            synchronized (c1889bm.j) {
                j2 = c1889bm.e;
            }
        }
        c2772w6L.e();
        C2815x6.D((C2815x6) c2772w6L.b, j2);
        synchronized (c1889bm.g) {
            i = c1889bm.b;
        }
        c2772w6L.e();
        C2815x6.z((C2815x6) c2772w6L.b, i);
        c2772w6L.e();
        C2815x6.A((C2815x6) c2772w6L.b, enumC2901z6);
        c2772w6L.e();
        C2815x6.B((C2815x6) c2772w6L.b, c2686u6);
        int i4 = c1976dm.h;
        c2772w6L.e();
        C2815x6.C((C2815x6) c2772w6L.b, i4);
        int i5 = z ? 2 : 1;
        c2772w6L.e();
        C2815x6.F((C2815x6) c2772w6L.b, i5);
        long jB = c1889bm.b();
        c2772w6L.e();
        C2815x6.H((C2815x6) c2772w6L.b, jB);
        jVar.k.getClass();
        long jCurrentTimeMillis = System.currentTimeMillis();
        c2772w6L.e();
        C2815x6.G((C2815x6) c2772w6L.b, jCurrentTimeMillis);
        int i6 = Settings.Global.getInt(context.getContentResolver(), "wifi_on", 0) != 0 ? 2 : 1;
        c2772w6L.e();
        C2815x6.I((C2815x6) c2772w6L.b, i6);
        byte[] bArrD = ((C2815x6) c2772w6L.c()).d();
        sQLiteDatabase.execSQL("UPDATE offline_signal_statistics SET value = value+1 WHERE statistic_name = 'completed_requests'");
        if (!z) {
            sQLiteDatabase.execSQL("UPDATE offline_signal_statistics SET value = value+1 WHERE statistic_name = 'failed_requests'");
        }
        LA.w(sQLiteDatabase, c1976dm.g.b(), bArrD);
        return null;
    }

    public boolean c(C2642t5 c2642t5) {
        long jCurrentTimeMillis = System.currentTimeMillis();
        synchronized (f) {
            try {
                if (!AbstractC2025es.y(new File(e(c2642t5.x().E()), "pcbc"), c2642t5.y().a())) {
                    g(4020, jCurrentTimeMillis);
                    return false;
                }
                String strF = f(c2642t5);
                SharedPreferences.Editor editorEdit = ((SharedPreferences) this.c).edit();
                editorEdit.putString("LATMTD".concat(String.valueOf((String) this.d)), strF);
                boolean zCommit = editorEdit.commit();
                if (zCommit) {
                    g(5015, jCurrentTimeMillis);
                } else {
                    g(4021, jCurrentTimeMillis);
                }
                return zCommit;
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:50:0x00ea A[Catch: all -> 0x002a, TryCatch #1 {all -> 0x002a, blocks: (B:5:0x000a, B:7:0x0019, B:9:0x0023, B:10:0x0028, B:14:0x002e, B:16:0x003e, B:19:0x0049, B:22:0x0054, B:31:0x009a, B:33:0x00ba, B:34:0x00bf, B:36:0x00c1, B:38:0x00cf, B:39:0x00d4, B:42:0x00d8, B:47:0x00e2, B:48:0x00e8, B:50:0x00ea, B:52:0x0120, B:53:0x0131, B:55:0x0137, B:56:0x013c, B:58:0x013e, B:60:0x0149, B:61:0x0150, B:63:0x0157, B:64:0x015e, B:66:0x0178, B:68:0x0184, B:69:0x0187, B:70:0x018a, B:71:0x018f, B:23:0x0075, B:25:0x007b, B:28:0x0086, B:29:0x0098), top: B:77:0x000a }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public boolean d(com.google.android.gms.internal.ads.C2642t5 r15, com.google.android.gms.internal.ads.C1 r16) {
        /*
            Method dump skipped, instructions count: 403
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Bs.d(com.google.android.gms.internal.ads.t5, com.google.android.gms.internal.ads.C1):boolean");
    }

    public File e(String str) {
        return new File(new File(((Context) this.b).getDir("pccache", 0), (String) this.d), str);
    }

    public void g(int i, long j) {
        ((InterfaceC2843xs) this.e).e(i, j);
    }

    public C2728v5 h(int i) {
        IA iaB;
        String str = (String) this.d;
        SharedPreferences sharedPreferences = (SharedPreferences) this.c;
        String string = i == 1 ? sharedPreferences.getString("LATMTD".concat(String.valueOf(str)), null) : sharedPreferences.getString("FBAMTD".concat(String.valueOf(str)), null);
        if (string != null) {
            long jCurrentTimeMillis = System.currentTimeMillis();
            try {
                byte[] bArrN = com.google.android.gms.common.util.c.n(string);
                C2905zA c2905zAW = BA.w(0, bArrN, bArrN.length);
                if (this.a) {
                    IA ia = IA.a;
                    C2305lB c2305lB = C2305lB.c;
                    iaB = IA.b;
                } else {
                    iaB = IA.b();
                }
                return C2728v5.C(c2905zAW, iaB);
            } catch (zzgzh unused) {
            } catch (NullPointerException unused2) {
                g(2029, jCurrentTimeMillis);
            } catch (RuntimeException unused3) {
                g(2032, jCurrentTimeMillis);
            }
        }
        return null;
    }

    public /* synthetic */ Bs(C2866yE c2866yE, YE ye, androidx.compose.animation.core.S0 s0, IOException iOException, boolean z) {
        this.b = c2866yE;
        this.c = ye;
        this.d = s0;
        this.e = iOException;
        this.a = z;
    }

    public Bs(Context context, int i, InterfaceC2843xs interfaceC2843xs, boolean z) {
        this.a = false;
        this.b = context;
        this.d = Integer.toString(i - 1);
        this.c = context.getSharedPreferences("pcvmspf", 0);
        this.e = interfaceC2843xs;
        this.a = z;
    }

    public Bs(Ir ir, Kr kr, Mr mr, Mr mr2, boolean z) {
        this.d = ir;
        this.e = kr;
        this.b = mr;
        this.c = mr2;
        this.a = z;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2491pj, com.google.android.gms.internal.ads.Pk
    /* renamed from: b, reason: collision with other method in class */
    public void mo10b(Object obj) {
        ((InterfaceC2266kF) obj).a(0, ((C2866yE) this.b).a, (YE) this.c, (androidx.compose.animation.core.S0) this.d, (IOException) this.e, this.a);
    }
}
