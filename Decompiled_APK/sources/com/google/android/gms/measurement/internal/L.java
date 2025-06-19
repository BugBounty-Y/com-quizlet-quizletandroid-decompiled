package com.google.android.gms.measurement.internal;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/* loaded from: classes2.dex */
public final class L implements Runnable {
    public final /* synthetic */ int a = 1;
    public final URL b;
    public final byte[] c;
    public final String d;
    public final Object e;
    public final Map f;
    public final /* synthetic */ androidx.compose.animation.core.J0 g;

    public L(M m, String str, URL url, byte[] bArr, Map map, K k) {
        this.g = m;
        com.google.android.gms.common.internal.u.e(str);
        com.google.android.gms.common.internal.u.h(url);
        this.b = url;
        this.c = bArr;
        this.e = k;
        this.d = str;
        this.f = map;
    }

    public void a(int i, IOException iOException, byte[] bArr, Map map) {
        X x = ((Y) ((H0) this.g).b).j;
        Y.k(x);
        x.c0(new G0(this, i, iOException, bArr, map));
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Not initialized variable reg: 13, insn: 0x0287: MOVE (r11 I:??[OBJECT, ARRAY]) = (r13 I:??[OBJECT, ARRAY]), block:B:141:0x0285 */
    /* JADX WARN: Not initialized variable reg: 13, insn: 0x028a: MOVE (r12 I:??[OBJECT, ARRAY]) = (r13 I:??[OBJECT, ARRAY]), block:B:142:0x0289 */
    /* JADX WARN: Removed duplicated region for block: B:163:0x02c5  */
    /* JADX WARN: Removed duplicated region for block: B:173:0x02fa  */
    /* JADX WARN: Removed duplicated region for block: B:177:0x02b0 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:179:0x0141 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:189:0x02e5 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:191:0x0163 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0156  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0178  */
    /* JADX WARN: Type inference failed for: r8v25, types: [java.io.OutputStream] */
    /* JADX WARN: Type inference failed for: r8v26, types: [java.io.OutputStream] */
    /* JADX WARN: Type inference failed for: r8v35, types: [java.io.OutputStream] */
    /* JADX WARN: Type inference failed for: r8v37 */
    /* JADX WARN: Type inference failed for: r8v38 */
    /* JADX WARN: Type inference failed for: r8v39 */
    /* JADX WARN: Type inference failed for: r8v40 */
    /* JADX WARN: Type inference failed for: r8v42, types: [boolean] */
    /* JADX WARN: Type inference failed for: r8v49 */
    /* JADX WARN: Type inference failed for: r8v50 */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 794
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.measurement.internal.L.run():void");
    }

    public L(H0 h0, String str, URL url, byte[] bArr, HashMap map, F0 f0) {
        this.g = h0;
        com.google.android.gms.common.internal.u.e(str);
        this.b = url;
        this.c = bArr;
        this.e = f0;
        this.d = str;
        this.f = map;
    }
}
