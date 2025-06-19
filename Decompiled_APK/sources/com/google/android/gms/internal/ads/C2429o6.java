package com.google.android.gms.internal.ads;

import android.os.Environment;
import android.os.SystemClock;
import android.util.Base64;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;

/* renamed from: com.google.android.gms.internal.ads.o6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2429o6 {
    public final C2472p6 a;
    public final C2301l7 b;
    public final boolean c;

    public C2429o6() {
        this.b = C2344m7.H();
        this.c = false;
        this.a = new C2472p6();
    }

    public final synchronized void a(InterfaceC2386n6 interfaceC2386n6) {
        if (this.c) {
            try {
                interfaceC2386n6.c(this.b);
            } catch (NullPointerException e) {
                com.google.android.gms.ads.internal.j.C.h.h("AdMobClearcutLogger.modify", e);
            }
        }
    }

    public final synchronized void b(int i) {
        if (this.c) {
            if (((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.f5)).booleanValue()) {
                d(i);
            } else {
                e(i);
            }
        }
    }

    public final synchronized String c(int i) {
        StringBuilder sb;
        C2301l7 c2301l7 = this.b;
        String strE = ((C2344m7) c2301l7.b).E();
        com.google.android.gms.ads.internal.j.C.k.getClass();
        long jElapsedRealtime = SystemClock.elapsedRealtime();
        String strEncodeToString = Base64.encodeToString(((C2344m7) c2301l7.c()).d(), 3);
        sb = new StringBuilder("id=");
        sb.append(strE);
        sb.append(",timestamp=");
        sb.append(jElapsedRealtime);
        sb.append(",event=");
        sb.append(i - 1);
        sb.append(",data=");
        sb.append(strEncodeToString);
        sb.append("\n");
        return sb.toString();
    }

    public final synchronized void d(int i) {
        File externalStorageDirectory = Environment.getExternalStorageDirectory();
        if (externalStorageDirectory == null) {
            return;
        }
        try {
            FileOutputStream fileOutputStream = new FileOutputStream(new File(new File(externalStorageDirectory, "clearcut_events.txt").getPath()), true);
            try {
                try {
                    fileOutputStream.write(c(i).getBytes());
                } catch (IOException unused) {
                    com.google.android.gms.ads.internal.util.A.l("Could not write Clearcut to file.");
                    try {
                        fileOutputStream.close();
                    } catch (IOException unused2) {
                        com.google.android.gms.ads.internal.util.A.l("Could not close Clearcut output stream.");
                    }
                }
            } finally {
                try {
                    fileOutputStream.close();
                } catch (IOException unused3) {
                    com.google.android.gms.ads.internal.util.A.l("Could not close Clearcut output stream.");
                }
            }
        } catch (FileNotFoundException unused4) {
            com.google.android.gms.ads.internal.util.A.l("Could not find file for Clearcut");
        }
    }

    public final synchronized void e(int i) {
        C2301l7 c2301l7 = this.b;
        c2301l7.e();
        C2344m7.x((C2344m7) c2301l7.b);
        ArrayList arrayListZ = com.google.android.gms.ads.internal.util.F.z();
        c2301l7.e();
        C2344m7.w((C2344m7) c2301l7.b, arrayListZ);
        byte[] bArrD = ((C2344m7) c2301l7.c()).d();
        C2472p6 c2472p6 = this.a;
        I3 i3 = new I3(c2472p6, bArrD);
        int i2 = i - 1;
        i3.b = i2;
        synchronized (i3) {
            c2472p6.c.execute(new RunnableC1989e(i3, 9));
        }
        com.google.android.gms.ads.internal.util.A.l("Logging Event with event code : ".concat(String.valueOf(Integer.toString(i2, 10))));
    }

    public C2429o6(C2472p6 c2472p6) {
        this.b = C2344m7.H();
        this.a = c2472p6;
        this.c = ((Boolean) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.e5)).booleanValue();
    }
}
