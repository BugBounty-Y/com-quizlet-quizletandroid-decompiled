package com.google.android.gms.internal.ads;

import android.net.Uri;
import androidx.compose.foundation.lazy.layout.C0429a;
import java.util.Collections;
import java.util.Map;

/* renamed from: com.google.android.gms.internal.ads.rF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2566rF {
    public final Uri a;
    public final C2563rC b;
    public final Iw c;
    public final C2695uF d;
    public final C1973dj e;
    public volatile boolean g;
    public long i;
    public C2891yx j;
    public InterfaceC2380n0 k;
    public boolean l;
    public final /* synthetic */ C2695uF m;
    public final C0429a f = new C0429a();
    public boolean h = true;

    public C2566rF(C2695uF c2695uF, Uri uri, Fw fw, Iw iw, C2695uF c2695uF2, C1973dj c1973dj) {
        this.m = c2695uF;
        this.a = uri;
        this.b = new C2563rC(fw);
        this.c = iw;
        this.d = c2695uF2;
        this.e = c1973dj;
        YE.a.getAndIncrement();
        this.j = b(0L);
    }

    /* JADX WARN: Can't wrap try/catch for region: R(22:14|(2:16|17)|18|19|(5:21|159|22|23|(18:25|26|143|33|(1:35)(1:36)|37|(1:39)(1:40)|41|(1:43)(1:44)|45|(1:47)(1:48)|49|(4:51|151|52|(16:54|55|(1:61)|62|(1:69)(1:66)|70|(1:77)|78|(1:80)|81|(1:(3:136|83|(6:157|85|1ae|94|(5:168|1d9|99|100|171)(1:170)|169)(2:167|111))(1:166))|(3:114|(1:116)|117)|139|118|164|(2:163|175)(1:165))(6:153|56|57|(0)|62|(13:64|69|70|(3:72|75|77)|78|(0)|81|(2:(0)(0)|169)|(0)|139|118|164|(0)(0))(0)))(4:57|(0)|62|(0)(0))|(2:124|(1:126))|127|145|128|129)(3:27|149|28))(1:32)|29|143|33|(0)(0)|37|(0)(0)|41|(0)(0)|45|(0)(0)|49|(0)(0)|(0)|127|145|128|129) */
    /* JADX WARN: Code restructure failed: missing block: B:67:0x016d, code lost:
    
        r0 = th;
     */
    /* JADX WARN: Removed duplicated region for block: B:114:0x01f9  */
    /* JADX WARN: Removed duplicated region for block: B:124:0x0215  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x01a8 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:163:0x022d A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:165:? A[LOOP:0: B:3:0x0004->B:165:?, LOOP_END, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:166:0x01f6 A[EDGE_INSN: B:166:0x01f6->B:112:0x01f6 BREAK  A[LOOP:1: B:82:0x01a6->B:169:0x01a6], SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00af A[Catch: all -> 0x016d, TryCatch #4 {all -> 0x016d, blocks: (B:33:0x00a4, B:35:0x00af, B:37:0x00bb, B:39:0x00c5, B:41:0x00d1, B:43:0x00db, B:45:0x00e7, B:47:0x00f1, B:49:0x0103, B:51:0x010d, B:52:0x0113, B:61:0x0141, B:62:0x0148, B:64:0x0152, B:66:0x0156, B:70:0x0171, B:72:0x0184, B:75:0x018b, B:77:0x018f, B:78:0x0193, B:80:0x0197, B:56:0x011d, B:59:0x0133, B:28:0x0077, B:31:0x0092), top: B:143:0x00a4 }] */
    /* JADX WARN: Removed duplicated region for block: B:36:0x00b9  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00c5 A[Catch: all -> 0x016d, TryCatch #4 {all -> 0x016d, blocks: (B:33:0x00a4, B:35:0x00af, B:37:0x00bb, B:39:0x00c5, B:41:0x00d1, B:43:0x00db, B:45:0x00e7, B:47:0x00f1, B:49:0x0103, B:51:0x010d, B:52:0x0113, B:61:0x0141, B:62:0x0148, B:64:0x0152, B:66:0x0156, B:70:0x0171, B:72:0x0184, B:75:0x018b, B:77:0x018f, B:78:0x0193, B:80:0x0197, B:56:0x011d, B:59:0x0133, B:28:0x0077, B:31:0x0092), top: B:143:0x00a4 }] */
    /* JADX WARN: Removed duplicated region for block: B:40:0x00cf  */
    /* JADX WARN: Removed duplicated region for block: B:43:0x00db A[Catch: all -> 0x016d, TryCatch #4 {all -> 0x016d, blocks: (B:33:0x00a4, B:35:0x00af, B:37:0x00bb, B:39:0x00c5, B:41:0x00d1, B:43:0x00db, B:45:0x00e7, B:47:0x00f1, B:49:0x0103, B:51:0x010d, B:52:0x0113, B:61:0x0141, B:62:0x0148, B:64:0x0152, B:66:0x0156, B:70:0x0171, B:72:0x0184, B:75:0x018b, B:77:0x018f, B:78:0x0193, B:80:0x0197, B:56:0x011d, B:59:0x0133, B:28:0x0077, B:31:0x0092), top: B:143:0x00a4 }] */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00e5  */
    /* JADX WARN: Removed duplicated region for block: B:47:0x00f1 A[Catch: all -> 0x016d, TryCatch #4 {all -> 0x016d, blocks: (B:33:0x00a4, B:35:0x00af, B:37:0x00bb, B:39:0x00c5, B:41:0x00d1, B:43:0x00db, B:45:0x00e7, B:47:0x00f1, B:49:0x0103, B:51:0x010d, B:52:0x0113, B:61:0x0141, B:62:0x0148, B:64:0x0152, B:66:0x0156, B:70:0x0171, B:72:0x0184, B:75:0x018b, B:77:0x018f, B:78:0x0193, B:80:0x0197, B:56:0x011d, B:59:0x0133, B:28:0x0077, B:31:0x0092), top: B:143:0x00a4 }] */
    /* JADX WARN: Removed duplicated region for block: B:48:0x0101  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x010d A[Catch: all -> 0x016d, TRY_LEAVE, TryCatch #4 {all -> 0x016d, blocks: (B:33:0x00a4, B:35:0x00af, B:37:0x00bb, B:39:0x00c5, B:41:0x00d1, B:43:0x00db, B:45:0x00e7, B:47:0x00f1, B:49:0x0103, B:51:0x010d, B:52:0x0113, B:61:0x0141, B:62:0x0148, B:64:0x0152, B:66:0x0156, B:70:0x0171, B:72:0x0184, B:75:0x018b, B:77:0x018f, B:78:0x0193, B:80:0x0197, B:56:0x011d, B:59:0x0133, B:28:0x0077, B:31:0x0092), top: B:143:0x00a4 }] */
    /* JADX WARN: Removed duplicated region for block: B:57:0x012f  */
    /* JADX WARN: Removed duplicated region for block: B:61:0x0141 A[Catch: all -> 0x016d, TryCatch #4 {all -> 0x016d, blocks: (B:33:0x00a4, B:35:0x00af, B:37:0x00bb, B:39:0x00c5, B:41:0x00d1, B:43:0x00db, B:45:0x00e7, B:47:0x00f1, B:49:0x0103, B:51:0x010d, B:52:0x0113, B:61:0x0141, B:62:0x0148, B:64:0x0152, B:66:0x0156, B:70:0x0171, B:72:0x0184, B:75:0x018b, B:77:0x018f, B:78:0x0193, B:80:0x0197, B:56:0x011d, B:59:0x0133, B:28:0x0077, B:31:0x0092), top: B:143:0x00a4 }] */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0152 A[Catch: all -> 0x016d, TryCatch #4 {all -> 0x016d, blocks: (B:33:0x00a4, B:35:0x00af, B:37:0x00bb, B:39:0x00c5, B:41:0x00d1, B:43:0x00db, B:45:0x00e7, B:47:0x00f1, B:49:0x0103, B:51:0x010d, B:52:0x0113, B:61:0x0141, B:62:0x0148, B:64:0x0152, B:66:0x0156, B:70:0x0171, B:72:0x0184, B:75:0x018b, B:77:0x018f, B:78:0x0193, B:80:0x0197, B:56:0x011d, B:59:0x0133, B:28:0x0077, B:31:0x0092), top: B:143:0x00a4 }] */
    /* JADX WARN: Removed duplicated region for block: B:69:0x0170  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0197 A[Catch: all -> 0x016d, TRY_LEAVE, TryCatch #4 {all -> 0x016d, blocks: (B:33:0x00a4, B:35:0x00af, B:37:0x00bb, B:39:0x00c5, B:41:0x00d1, B:43:0x00db, B:45:0x00e7, B:47:0x00f1, B:49:0x0103, B:51:0x010d, B:52:0x0113, B:61:0x0141, B:62:0x0148, B:64:0x0152, B:66:0x0156, B:70:0x0171, B:72:0x0184, B:75:0x018b, B:77:0x018f, B:78:0x0193, B:80:0x0197, B:56:0x011d, B:59:0x0133, B:28:0x0077, B:31:0x0092), top: B:143:0x00a4 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a() throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 558
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2566rF.a():void");
    }

    public final C2891yx b(long j) {
        Map map = Collections.EMPTY_MAP;
        Map map2 = C2695uF.V;
        Uri uri = this.a;
        if (uri != null) {
            return new C2891yx(uri, map2, j, -1L, 6);
        }
        throw new IllegalStateException("The uri must be set.");
    }
}
