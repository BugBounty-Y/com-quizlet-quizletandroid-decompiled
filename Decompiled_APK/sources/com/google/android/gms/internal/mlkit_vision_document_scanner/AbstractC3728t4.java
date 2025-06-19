package com.google.android.gms.internal.mlkit_vision_document_scanner;

import android.os.Build;
import java.io.File;
import java.io.IOException;

/* renamed from: com.google.android.gms.internal.mlkit_vision_document_scanner.t4, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC3728t4 {
    public static final String[] a = {"com.android.", "com.google.", "com.chrome.", "com.nest.", "com.waymo.", "com.waze"};
    public static final String[] b;
    public static final String[] c;

    static {
        String str = Build.HARDWARE;
        b = new String[]{"media", (str.equals("goldfish") || str.equals("ranchu")) ? "androidx.test.services.storage.runfiles" : ""};
        c = new String[]{"", "", "com.google.android.apps.docs.storage.legacy"};
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0054, code lost:
    
        if (r14.a == false) goto L66;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x0097, code lost:
    
        if (r14 != false) goto L66;
     */
    /* JADX WARN: Removed duplicated region for block: B:101:0x0197 A[Catch: IOException -> 0x0182, FileNotFoundException -> 0x0185, TryCatch #8 {FileNotFoundException -> 0x0185, IOException -> 0x0182, blocks: (B:78:0x012c, B:81:0x014b, B:83:0x0153, B:85:0x015b, B:87:0x0163, B:89:0x016b, B:91:0x0176, B:129:0x01ef, B:131:0x01f3, B:101:0x0197, B:103:0x019d, B:105:0x01a3, B:108:0x01ae, B:110:0x01b9, B:112:0x01bd, B:114:0x01c1, B:117:0x01cc, B:118:0x01ce, B:120:0x01d9, B:122:0x01dd, B:124:0x01e1, B:127:0x01ec, B:137:0x01fd, B:138:0x0202, B:139:0x0203, B:144:0x0208, B:145:0x020d, B:146:0x020e, B:98:0x0188, B:147:0x020f, B:148:0x0218, B:149:0x0219, B:150:0x0226, B:151:0x0227, B:152:0x0234), top: B:177:0x012c }] */
    /* JADX WARN: Removed duplicated region for block: B:131:0x01f3 A[Catch: IOException -> 0x0182, FileNotFoundException -> 0x0185, TryCatch #8 {FileNotFoundException -> 0x0185, IOException -> 0x0182, blocks: (B:78:0x012c, B:81:0x014b, B:83:0x0153, B:85:0x015b, B:87:0x0163, B:89:0x016b, B:91:0x0176, B:129:0x01ef, B:131:0x01f3, B:101:0x0197, B:103:0x019d, B:105:0x01a3, B:108:0x01ae, B:110:0x01b9, B:112:0x01bd, B:114:0x01c1, B:117:0x01cc, B:118:0x01ce, B:120:0x01d9, B:122:0x01dd, B:124:0x01e1, B:127:0x01ec, B:137:0x01fd, B:138:0x0202, B:139:0x0203, B:144:0x0208, B:145:0x020d, B:146:0x020e, B:98:0x0188, B:147:0x020f, B:148:0x0218, B:149:0x0219, B:150:0x0226, B:151:0x0227, B:152:0x0234), top: B:177:0x012c }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.io.InputStream a(final android.content.Context r12, android.net.Uri r13, com.google.android.gms.internal.mlkit_vision_document_scanner.T3 r14) throws java.io.IOException {
        /*
            Method dump skipped, instructions count: 613
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3728t4.a(android.content.Context, android.net.Uri, com.google.android.gms.internal.mlkit_vision_document_scanner.T3):java.io.InputStream");
    }

    public static String b(File file) throws IOException {
        String canonicalPath = file.getCanonicalPath();
        return !canonicalPath.endsWith("/") ? canonicalPath.concat("/") : canonicalPath;
    }
}
