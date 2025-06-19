package com.google.android.gms.internal.ads;

import java.io.File;
import java.text.DecimalFormat;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/* renamed from: com.google.android.gms.internal.ads.Xd, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1800Xd extends AbstractC1794Wd {
    public static final Set f = Collections.synchronizedSet(new HashSet());
    public static final DecimalFormat g = new DecimalFormat("#,###");
    public File d;
    public boolean e;

    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    public final void l() {
        this.e = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:134:0x0379  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x0389  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x03a0  */
    /* JADX WARN: Removed duplicated region for block: B:142:0x03bc  */
    /* JADX WARN: Type inference failed for: r7v12 */
    /* JADX WARN: Type inference failed for: r7v14 */
    /* JADX WARN: Type inference failed for: r7v8 */
    @Override // com.google.android.gms.internal.ads.AbstractC1794Wd
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean r(java.lang.String r31) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 1003
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1800Xd.r(java.lang.String):boolean");
    }

    public final File u(File file) {
        return new File(new File(this.d, String.valueOf(file.getName()).concat(".done")).getPath());
    }
}
