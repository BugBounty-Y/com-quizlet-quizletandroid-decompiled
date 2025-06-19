package androidx.compose.ui.focus;

import androidx.activity.K;
import androidx.camera.camera2.internal.AbstractC0147y;
import androidx.collection.A;
import androidx.compose.foundation.lazy.grid.w;
import androidx.compose.foundation.text.z0;
import androidx.compose.material3.internal.O;
import androidx.compose.ui.node.T;
import androidx.compose.ui.platform.C0960p;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.J;

/* loaded from: classes.dex */
public final class j implements h {
    public final C0960p a;
    public final z0 b;
    public final K c;
    public final K d;
    public final O e;
    public final f g;
    public A j;
    public final t f = new t();
    public final com.bumptech.glide.manager.p h = new com.bumptech.glide.manager.p(3);
    public final androidx.compose.ui.q i = new FocusPropertiesElement(new m()).g(new T() { // from class: androidx.compose.ui.focus.FocusOwnerImpl$modifier$2
        public final boolean equals(Object obj) {
            return obj == this;
        }

        public final int hashCode() {
            return this.b.f.hashCode();
        }

        @Override // androidx.compose.ui.node.T
        public final androidx.compose.ui.p l() {
            return this.b.f;
        }

        @Override // androidx.compose.ui.node.T
        public final /* bridge */ /* synthetic */ void n(androidx.compose.ui.p pVar) {
        }
    });

    public j(z0 z0Var, C0960p c0960p, z0 z0Var2, K k, K k2, O o) {
        this.a = c0960p;
        this.b = z0Var2;
        this.c = k;
        this.d = k2;
        this.e = o;
        this.g = new f(z0Var, new K(0, this, j.class, "invalidateOwnerFocusState", "invalidateOwnerFocusState()V", 0, 5));
    }

    public final boolean b(int i, boolean z, boolean z2) {
        int iK;
        com.bumptech.glide.manager.p pVar = this.h;
        g gVar = g.c;
        try {
            if (pVar.a) {
                com.bumptech.glide.manager.p.a(pVar);
            }
            pVar.a = true;
            ((androidx.compose.runtime.collection.b) pVar.c).b(gVar);
            t tVar = this.f;
            boolean zE = (z || !((iK = AbstractC0147y.k(a.y(tVar, i))) == 1 || iK == 2 || iK == 3)) ? a.e(tVar, z) : false;
            if (zE && z2) {
                this.c.invoke();
            }
            return zE;
        } finally {
            com.bumptech.glide.manager.p.d(pVar);
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:19:0x00b6, code lost:
    
        r38 = r8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:20:0x00c0, code lost:
    
        if (((((~r12) << 6) & r12) & (-9187201950435737472L)) == 0) goto L67;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x00c2, code lost:
    
        r5 = r11.b(r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:22:0x00c8, code lost:
    
        if (r11.e != 0) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x00d9, code lost:
    
        if (((r11.a[r5 >> 3] >> ((r5 & 7) << 3)) & 255) != 254) goto L26;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x00db, code lost:
    
        r40 = 16;
        r24 = 128;
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x00e1, code lost:
    
        r5 = r11.c;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x00e3, code lost:
    
        if (r5 <= r2) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x00e5, code lost:
    
        r12 = r11.d;
        r6 = kotlin.D.b;
     */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x00f7, code lost:
    
        if (java.lang.Long.compareUnsigned(r12 * 32, r5 * 25) > 0) goto L52;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x00f9, code lost:
    
        r5 = r11.a;
        r6 = r11.c;
        r12 = r11.b;
        r13 = (r6 + 7) >> 3;
        r2 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x0107, code lost:
    
        if (r2 >= r13) goto L431;
     */
    /* JADX WARN: Code restructure failed: missing block: B:32:0x0109, code lost:
    
        r7 = r5[r2] & (-9187201950435737472L);
        r5[r2] = ((~r7) + (r7 >>> 7)) & (-72340172838076674L);
        r2 = r2 + 1;
        r3 = r3;
        r4 = r4;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0126, code lost:
    
        r40 = r3;
        r41 = r4;
        r24 = 128;
        r2 = kotlin.collections.C4933y.D(r5);
        r3 = r2 - 1;
        r5[r3] = (r5[r3] & 72057594037927935L) | (-72057594037927936L);
        r5[r2] = r5[0];
        r2 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0147, code lost:
    
        if (r2 == r6) goto L432;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x0149, code lost:
    
        r3 = r2 >> 3;
        r4 = (r2 & 7) << 3;
        r7 = (r5[r3] >> r4) & 255;
     */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x0156, code lost:
    
        if (r7 != 128) goto L38;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x0158, code lost:
    
        r2 = r2 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:39:0x015d, code lost:
    
        if (r7 == 254) goto L433;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x0160, code lost:
    
        r7 = java.lang.Long.hashCode(r12[r2]) * (-862048943);
        r8 = (r7 ^ (r7 << 16)) >>> 7;
        r13 = r11.b(r8);
        r8 = r8 & r6;
        r22 = r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x0185, code lost:
    
        if ((((r13 - r8) & r6) / 8) != (((r22 - r8) & r6) / 8)) goto L45;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x0187, code lost:
    
        r2 = r6;
        r5[r3] = (r5[r3] & (~(255 << r4))) | ((r7 & 127) << r4);
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, "<this>");
        r5[r5.length - 1] = (r5[0] & 72057594037927935L) | Long.MIN_VALUE;
        r3 = r22 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x01aa, code lost:
    
        r6 = r2;
        r2 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:45:0x01ad, code lost:
    
        r2 = r6;
        r6 = r13 >> 3;
        r42 = r5[r6];
        r8 = (r13 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:46:0x01bc, code lost:
    
        if (((r42 >> r8) & 255) != 128) goto L48;
     */
    /* JADX WARN: Code restructure failed: missing block: B:47:0x01be, code lost:
    
        r5[r6] = (r42 & (~(255 << r8))) | ((r7 & 127) << r8);
        r5[r3] = (r5[r3] & (~(255 << r4))) | (128 << r4);
        r12[r13] = r12[r22];
        r12[r22] = 0;
        r4 = r22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:48:0x01e8, code lost:
    
        r5[r6] = (r42 & (~(255 << r8))) | ((r7 & 127) << r8);
        r6 = r12[r13];
        r12[r13] = r12[r22];
        r12[r22] = r6;
        r4 = r22 - 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:49:0x0204, code lost:
    
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, "<this>");
        r5[r5.length - 1] = (r5[0] & 72057594037927935L) | Long.MIN_VALUE;
        r3 = r4 + 1;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x0215, code lost:
    
        r11.e = androidx.collection.S.a(r11.c) - r11.d;
     */
    /* JADX WARN: Code restructure failed: missing block: B:52:0x0224, code lost:
    
        r40 = 16;
        r41 = r4;
        r24 = 128;
        r2 = androidx.collection.S.b(r11.c);
        r3 = r11.a;
        r4 = r11.b;
        r5 = r11.c;
        r11.c(r2);
        r2 = r11.a;
        r6 = r11.b;
        r7 = r11.c;
        r8 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:53:0x0241, code lost:
    
        if (r8 >= r5) goto L439;
     */
    /* JADX WARN: Code restructure failed: missing block: B:55:0x0251, code lost:
    
        if (((r3[r8 >> 3] >> ((r8 & 7) << 3)) & 255) >= 128) goto L57;
     */
    /* JADX WARN: Code restructure failed: missing block: B:56:0x0253, code lost:
    
        r12 = r4[r8];
        r17 = java.lang.Long.hashCode(r12) * (-862048943);
        r17 = r17 ^ (r17 << 16);
        r18 = r2;
        r2 = r11.b(r17 >>> 7);
        r2 = r17 & 127;
        r17 = r3;
        r20 = r2 >> 3;
        r21 = (r2 & 7) << 3;
        r2 = (r18[r20] & (~(255 << r21))) | (r2 << r21);
        r18[r20] = r2;
        r18[(((r2 - 7) & r7) + (r7 & 7)) >> 3] = r2;
        r6[r2] = r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:57:0x0292, code lost:
    
        r18 = r2;
        r17 = r3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:58:0x0296, code lost:
    
        r8 = r8 + 1;
        r3 = r17;
        r2 = r18;
     */
    /* JADX WARN: Code restructure failed: missing block: B:59:0x029d, code lost:
    
        r37 = r11.b(r41);
     */
    /* JADX WARN: Code restructure failed: missing block: B:60:0x02a4, code lost:
    
        r37 = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:61:0x02a6, code lost:
    
        r11.d++;
        r2 = r11.e;
        r3 = r11.a;
        r4 = r37 >> 3;
        r5 = r3[r4];
        r7 = (r37 & 7) << 3;
     */
    /* JADX WARN: Code restructure failed: missing block: B:62:0x02be, code lost:
    
        if (((r5 >> r7) & 255) != r24) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:63:0x02c0, code lost:
    
        r8 = r38;
     */
    /* JADX WARN: Code restructure failed: missing block: B:64:0x02c3, code lost:
    
        r8 = 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:65:0x02c5, code lost:
    
        r11.e = r2 - r8;
        r2 = r11.c;
        r5 = (r5 & (~(255 << r7))) | (r14 << r7);
        r3[r4] = r5;
        r3[(((r37 - 7) & r2) + (r2 & 7)) >> 3] = r5;
     */
    /* JADX WARN: Code restructure failed: missing block: B:85:0x036e, code lost:
    
        if (((r11 & ((~r11) << 6)) & (-9187201950435737472L)) == 0) goto L89;
     */
    /* JADX WARN: Code restructure failed: missing block: B:86:0x0370, code lost:
    
        r7 = -1;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:110:0x03d5  */
    /* JADX WARN: Removed duplicated region for block: B:145:0x043f A[PHI: r9
  0x043f: PHI (r9v14 androidx.compose.runtime.collection.b) = 
  (r9v43 androidx.compose.runtime.collection.b)
  (r9v44 androidx.compose.runtime.collection.b)
  (r9v45 androidx.compose.runtime.collection.b)
 binds: [B:126:0x0405, B:128:0x0409, B:143:0x043a] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:160:0x046d  */
    /* JADX WARN: Type inference failed for: r10v0 */
    /* JADX WARN: Type inference failed for: r10v1, types: [int] */
    /* JADX WARN: Type inference failed for: r10v2 */
    /* JADX WARN: Type inference failed for: r10v26 */
    /* JADX WARN: Type inference failed for: r10v3, types: [int] */
    /* JADX WARN: Type inference failed for: r11v15 */
    /* JADX WARN: Type inference failed for: r11v16, types: [int] */
    /* JADX WARN: Type inference failed for: r11v17 */
    /* JADX WARN: Type inference failed for: r11v18, types: [int] */
    /* JADX WARN: Type inference failed for: r11v19 */
    /* JADX WARN: Type inference failed for: r11v20, types: [int] */
    /* JADX WARN: Type inference failed for: r11v21 */
    /* JADX WARN: Type inference failed for: r11v22, types: [int] */
    /* JADX WARN: Type inference failed for: r11v24 */
    /* JADX WARN: Type inference failed for: r11v25 */
    /* JADX WARN: Type inference failed for: r2v100 */
    /* JADX WARN: Type inference failed for: r2v101 */
    /* JADX WARN: Type inference failed for: r2v102 */
    /* JADX WARN: Type inference failed for: r2v103 */
    /* JADX WARN: Type inference failed for: r2v104 */
    /* JADX WARN: Type inference failed for: r2v14, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v15, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v19, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v20, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v24 */
    /* JADX WARN: Type inference failed for: r2v25, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v26, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v27 */
    /* JADX WARN: Type inference failed for: r2v28 */
    /* JADX WARN: Type inference failed for: r2v29 */
    /* JADX WARN: Type inference failed for: r2v30 */
    /* JADX WARN: Type inference failed for: r2v31 */
    /* JADX WARN: Type inference failed for: r2v34 */
    /* JADX WARN: Type inference failed for: r2v35, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r2v36, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r2v37 */
    /* JADX WARN: Type inference failed for: r2v38 */
    /* JADX WARN: Type inference failed for: r2v39 */
    /* JADX WARN: Type inference failed for: r2v40 */
    /* JADX WARN: Type inference failed for: r3v29 */
    /* JADX WARN: Type inference failed for: r3v30 */
    /* JADX WARN: Type inference failed for: r3v31 */
    /* JADX WARN: Type inference failed for: r3v32 */
    /* JADX WARN: Type inference failed for: r3v33 */
    /* JADX WARN: Type inference failed for: r3v34, types: [int] */
    /* JADX WARN: Type inference failed for: r3v36 */
    /* JADX WARN: Type inference failed for: r3v37, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r3v38 */
    /* JADX WARN: Type inference failed for: r3v39 */
    /* JADX WARN: Type inference failed for: r3v40, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r3v42 */
    /* JADX WARN: Type inference failed for: r3v43, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r3v44 */
    /* JADX WARN: Type inference failed for: r3v45 */
    /* JADX WARN: Type inference failed for: r3v46, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r3v71 */
    /* JADX WARN: Type inference failed for: r3v72 */
    /* JADX WARN: Type inference failed for: r3v73 */
    /* JADX WARN: Type inference failed for: r3v74 */
    /* JADX WARN: Type inference failed for: r3v75 */
    /* JADX WARN: Type inference failed for: r3v76 */
    /* JADX WARN: Type inference failed for: r3v77 */
    /* JADX WARN: Type inference failed for: r3v78 */
    /* JADX WARN: Type inference failed for: r3v79 */
    /* JADX WARN: Type inference failed for: r5v10 */
    /* JADX WARN: Type inference failed for: r5v11 */
    /* JADX WARN: Type inference failed for: r5v12 */
    /* JADX WARN: Type inference failed for: r5v13, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r5v14, types: [java.util.ArrayList] */
    /* JADX WARN: Type inference failed for: r5v15 */
    /* JADX WARN: Type inference failed for: r5v16 */
    /* JADX WARN: Type inference failed for: r5v40 */
    /* JADX WARN: Type inference failed for: r5v41 */
    /* JADX WARN: Type inference failed for: r5v7 */
    /* JADX WARN: Type inference failed for: r5v8, types: [java.util.List] */
    /* JADX WARN: Type inference failed for: r5v9 */
    /* JADX WARN: Type inference failed for: r6v115 */
    /* JADX WARN: Type inference failed for: r6v116 */
    /* JADX WARN: Type inference failed for: r6v16 */
    /* JADX WARN: Type inference failed for: r6v17, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r6v18 */
    /* JADX WARN: Type inference failed for: r6v19, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r6v20, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r6v21 */
    /* JADX WARN: Type inference failed for: r6v22 */
    /* JADX WARN: Type inference failed for: r6v23 */
    /* JADX WARN: Type inference failed for: r6v24 */
    /* JADX WARN: Type inference failed for: r6v5 */
    /* JADX WARN: Type inference failed for: r6v6 */
    /* JADX WARN: Type inference failed for: r7v16 */
    /* JADX WARN: Type inference failed for: r7v17 */
    /* JADX WARN: Type inference failed for: r7v18 */
    /* JADX WARN: Type inference failed for: r7v19, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r7v20 */
    /* JADX WARN: Type inference failed for: r7v21 */
    /* JADX WARN: Type inference failed for: r7v22, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r7v25 */
    /* JADX WARN: Type inference failed for: r7v26 */
    /* JADX WARN: Type inference failed for: r7v37 */
    /* JADX WARN: Type inference failed for: r7v38, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r7v47 */
    /* JADX WARN: Type inference failed for: r7v48, types: [int] */
    /* JADX WARN: Type inference failed for: r7v88 */
    /* JADX WARN: Type inference failed for: r7v91 */
    /* JADX WARN: Type inference failed for: r7v94 */
    /* JADX WARN: Type inference failed for: r7v95 */
    /* JADX WARN: Type inference failed for: r7v96 */
    /* JADX WARN: Type inference failed for: r7v97 */
    /* JADX WARN: Type inference failed for: r9v23 */
    /* JADX WARN: Type inference failed for: r9v24, types: [int] */
    /* JADX WARN: Type inference failed for: r9v25 */
    /* JADX WARN: Type inference failed for: r9v26, types: [int] */
    /* JADX WARN: Type inference failed for: r9v37 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean c(android.view.KeyEvent r47, kotlin.jvm.functions.Function0 r48) {
        /*
            Method dump skipped, instructions count: 1674
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.j.c(android.view.KeyEvent, kotlin.jvm.functions.Function0):boolean");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:26:0x005f A[PHI: r11
  0x005f: PHI (r11v12 androidx.compose.ui.focus.p) = (r11v9 androidx.compose.ui.focus.p), (r11v16 androidx.compose.ui.focus.p) binds: [B:38:0x007c, B:24:0x005a] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Type inference failed for: r11v2, types: [java.lang.Object, kotlin.jvm.functions.Function1] */
    /* JADX WARN: Type inference failed for: r11v4, types: [java.lang.Object, kotlin.jvm.functions.Function1] */
    /* JADX WARN: Type inference failed for: r3v11, types: [androidx.compose.ui.node.o0] */
    /* JADX WARN: Type inference failed for: r3v5, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r3v6 */
    /* JADX WARN: Type inference failed for: r3v7 */
    /* JADX WARN: Type inference failed for: r3v8 */
    /* JADX WARN: Type inference failed for: r5v11 */
    /* JADX WARN: Type inference failed for: r5v12, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v13, types: [androidx.compose.ui.focus.t] */
    /* JADX WARN: Type inference failed for: r5v14 */
    /* JADX WARN: Type inference failed for: r5v15, types: [androidx.compose.ui.p] */
    /* JADX WARN: Type inference failed for: r5v16, types: [java.lang.Object] */
    /* JADX WARN: Type inference failed for: r5v17 */
    /* JADX WARN: Type inference failed for: r5v18 */
    /* JADX WARN: Type inference failed for: r5v19 */
    /* JADX WARN: Type inference failed for: r5v20 */
    /* JADX WARN: Type inference failed for: r5v21 */
    /* JADX WARN: Type inference failed for: r5v22 */
    /* JADX WARN: Type inference failed for: r6v11 */
    /* JADX WARN: Type inference failed for: r6v12 */
    /* JADX WARN: Type inference failed for: r6v13 */
    /* JADX WARN: Type inference failed for: r6v14 */
    /* JADX WARN: Type inference failed for: r6v3 */
    /* JADX WARN: Type inference failed for: r6v4 */
    /* JADX WARN: Type inference failed for: r6v5 */
    /* JADX WARN: Type inference failed for: r6v6, types: [androidx.compose.runtime.collection.b] */
    /* JADX WARN: Type inference failed for: r6v7 */
    /* JADX WARN: Type inference failed for: r6v8 */
    /* JADX WARN: Type inference failed for: r6v9, types: [androidx.compose.runtime.collection.b] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Boolean d(int r19, androidx.compose.ui.geometry.c r20, kotlin.jvm.functions.Function1 r21) {
        /*
            Method dump skipped, instructions count: 500
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.compose.ui.focus.j.d(int, androidx.compose.ui.geometry.c, kotlin.jvm.functions.Function1):java.lang.Boolean");
    }

    public final boolean e(int i) {
        J j = new J();
        j.a = Boolean.FALSE;
        Boolean boolD = d(i, (androidx.compose.ui.geometry.c) this.d.invoke(), new androidx.compose.foundation.lazy.u(j, i, 4));
        if (boolD != null && j.a != null) {
            Boolean bool = Boolean.TRUE;
            if (!boolD.equals(bool) || !Intrinsics.b(j.a, bool)) {
                if (i != 1 && i != 2) {
                    return ((Boolean) this.b.invoke(new c(i))).booleanValue();
                }
                if (b(i, false, false)) {
                    Boolean boolD2 = d(i, null, new w(i, 4));
                    if (boolD2 != null ? boolD2.booleanValue() : false) {
                    }
                }
            }
            return true;
        }
        return false;
    }
}
