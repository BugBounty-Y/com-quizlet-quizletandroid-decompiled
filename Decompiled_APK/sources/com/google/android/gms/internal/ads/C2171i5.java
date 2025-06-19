package com.google.android.gms.internal.ads;

import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/* renamed from: com.google.android.gms.internal.ads.i5, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2171i5 extends AbstractCallableC2599s5 {
    public static final Os k = new Os(6);
    public final Z3 h;
    public final Context i;
    public final C2326lq j;

    public C2171i5(Z4 z4, C1864b4 c1864b4, int i, Context context, Z3 z3, C2326lq c2326lq) {
        super(z4, "5l2BxulTXy+0Wovy9T0xreNvMgccuxz9Mfzqj2nIzDWreku9cf/hyHYbFP2gke7n", "rfz55QLsxMWzB2XqDjYWCElC2tXCWyMh5Hq3cP2KfWk=", c1864b4, i, 27);
        this.i = context;
        this.h = z3;
        this.j = c2326lq;
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0042 A[Catch: all -> 0x003f, TryCatch #2 {all -> 0x003f, blocks: (B:4:0x000e, B:6:0x0018, B:8:0x001e, B:14:0x002a, B:16:0x0034, B:64:0x00ed, B:65:0x00f3, B:21:0x0042, B:23:0x0048, B:63:0x00ea, B:24:0x004e, B:26:0x0075, B:28:0x007b, B:30:0x0081, B:33:0x0089, B:39:0x0095, B:41:0x009b, B:45:0x00a6, B:47:0x00ad, B:46:0x00ab, B:48:0x00b0, B:50:0x00b6, B:52:0x00bc, B:42:0x00a0, B:55:0x00c3, B:57:0x00d8, B:61:0x00e1), top: B:83:0x000e }] */
    @Override // com.google.android.gms.internal.ads.AbstractCallableC2599s5
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a() {
        /*
            Method dump skipped, instructions count: 318
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2171i5.a():void");
    }

    public final String b() throws PackageManager.NameNotFoundException, CertificateException {
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            C2601s7 c2601s7 = AbstractC2773w7.C2;
            com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
            byte[] bArrB = AbstractC1865b5.b((String) rVar.c.a(c2601s7));
            ArrayList arrayList = new ArrayList();
            arrayList.add(certificateFactory.generateCertificate(new ByteArrayInputStream(bArrB)));
            if (!Build.TYPE.equals("user")) {
                arrayList.add(certificateFactory.generateCertificate(new ByteArrayInputStream(AbstractC1865b5.b((String) rVar.c.a(AbstractC2773w7.D2)))));
            }
            Context context = this.i;
            String packageName = context.getPackageName();
            this.a.getClass();
            if (Build.VERSION.SDK_INT <= 30 && !Build.VERSION.CODENAME.equals("S")) {
                return null;
            }
            C1985dw c1985dw = new C1985dw();
            context.getPackageManager().requestChecksums(packageName, false, 8, arrayList, new B4(c1985dw));
            return (String) c1985dw.get();
        } catch (PackageManager.NameNotFoundException | InterruptedException | NoClassDefFoundError | CertificateEncodingException | CertificateException | ExecutionException unused) {
            return null;
        }
    }

    public final C2899z4 c() {
        String str;
        RunnableFutureC2161hw runnableFutureC2161hw;
        C2601s7 c2601s7 = AbstractC2773w7.N2;
        com.google.android.gms.ads.internal.client.r rVar = com.google.android.gms.ads.internal.client.r.d;
        int iIntValue = ((Boolean) rVar.c.a(c2601s7)).booleanValue() ? ((Integer) rVar.c.a(AbstractC2773w7.S2)).intValue() : this.h.w();
        C2899z4 c2899z4 = new C2899z4((String) this.e.invoke(null, this.i, Boolean.FALSE, ""));
        C2326lq c2326lq = this.j;
        if (c2326lq == null || (runnableFutureC2161hw = (RunnableFutureC2161hw) c2326lq.b) == null) {
            str = "E";
        } else {
            try {
                str = (String) runnableFutureC2161hw.get(iIntValue, TimeUnit.MILLISECONDS);
            } catch (InterruptedException | ExecutionException | TimeoutException unused) {
            }
        }
        c2899z4.O = str;
        return c2899z4;
    }
}
