package androidx.paging;

import androidx.compose.foundation.text.C0494i0;
import androidx.compose.material3.C0676l1;
import androidx.datastore.core.C1087t;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import kotlin.NoWhenBranchMatchedException;
import kotlin.Unit;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5027k0;
import kotlinx.coroutines.flow.InterfaceC4992i;

/* renamed from: androidx.paging.q0, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1336q0 {
    public final Object a;
    public final S0 b;
    public final C0676l1 c;
    public final C1329n d;
    public final com.google.android.gms.internal.instantapps.a e;
    public final AtomicBoolean f;
    public final kotlinx.coroutines.channels.h g;
    public final C1337r0 h;
    public final C5027k0 i;
    public final J0 j;

    public C1336q0(Object obj, S0 pagingSource, C0676l1 config, C1329n retryFlow, T0 t0, androidx.activity.K jumpCallback) {
        Intrinsics.checkNotNullParameter(pagingSource, "pagingSource");
        Intrinsics.checkNotNullParameter(config, "config");
        Intrinsics.checkNotNullParameter(retryFlow, "retryFlow");
        Intrinsics.checkNotNullParameter(jumpCallback, "jumpCallback");
        this.a = obj;
        this.b = pagingSource;
        this.c = config;
        this.d = retryFlow;
        this.e = new com.google.android.gms.internal.instantapps.a(15);
        this.f = new AtomicBoolean(false);
        this.g = D1.a(-2, 6, null);
        this.h = new C1337r0(config);
        C5027k0 controller = kotlinx.coroutines.E.d();
        this.i = controller;
        C1328m0 block = new C1328m0(this, null);
        Intrinsics.checkNotNullParameter(controller, "controller");
        Intrinsics.checkNotNullParameter(block, "block");
        this.j = new J0(new C1330n0(this, null), AbstractC1348x.e(new C1323k(controller, block, null)));
    }

    public static final Object a(C1336q0 c1336q0, J0 j0, G g, kotlin.coroutines.jvm.internal.i iVar) {
        c1336q0.getClass();
        InterfaceC4992i interfaceC4992iF = AbstractC1348x.f(j0, new X(null, c1336q0, g));
        Y operation = new Y(g, null);
        Intrinsics.checkNotNullParameter(interfaceC4992iF, "<this>");
        Intrinsics.checkNotNullParameter(operation, "operation");
        Object objB = kotlinx.coroutines.flow.e0.f(new C1087t(new C1338s(interfaceC4992iF, operation, null)), -1).b(new C0494i0(7, c1336q0, g), iVar);
        return objB == kotlin.coroutines.intrinsics.a.a ? objB : Unit.a;
    }

    /* JADX WARN: Code restructure failed: missing block: B:257:0x039d, code lost:
    
        r9.getClass();
        r3 = r15;
        r8 = r19;
        r12 = r20;
        r15 = r2;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Path cross not found for [B:55:0x028c, B:54:0x0288], limit reached: 245 */
    /* JADX WARN: Removed duplicated region for block: B:101:0x03a1  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x0406  */
    /* JADX WARN: Removed duplicated region for block: B:133:0x046d  */
    /* JADX WARN: Removed duplicated region for block: B:138:0x0486  */
    /* JADX WARN: Removed duplicated region for block: B:166:0x050a  */
    /* JADX WARN: Removed duplicated region for block: B:180:0x056f  */
    /* JADX WARN: Removed duplicated region for block: B:192:0x059f  */
    /* JADX WARN: Removed duplicated region for block: B:193:0x05a2  */
    /* JADX WARN: Removed duplicated region for block: B:197:0x05cd  */
    /* JADX WARN: Removed duplicated region for block: B:203:0x060a A[Catch: all -> 0x0622, TryCatch #2 {all -> 0x0622, blocks: (B:198:0x05d5, B:199:0x05f0, B:201:0x0606, B:203:0x060a, B:205:0x0612, B:207:0x0616, B:210:0x061e, B:209:0x061c, B:213:0x0624), top: B:242:0x05d5 }] */
    /* JADX WARN: Removed duplicated region for block: B:207:0x0616 A[Catch: all -> 0x0622, TryCatch #2 {all -> 0x0622, blocks: (B:198:0x05d5, B:199:0x05f0, B:201:0x0606, B:203:0x060a, B:205:0x0612, B:207:0x0616, B:210:0x061e, B:209:0x061c, B:213:0x0624), top: B:242:0x05d5 }] */
    /* JADX WARN: Removed duplicated region for block: B:209:0x061c A[Catch: all -> 0x0622, TryCatch #2 {all -> 0x0622, blocks: (B:198:0x05d5, B:199:0x05f0, B:201:0x0606, B:203:0x060a, B:205:0x0612, B:207:0x0616, B:210:0x061e, B:209:0x061c, B:213:0x0624), top: B:242:0x05d5 }] */
    /* JADX WARN: Removed duplicated region for block: B:216:0x064f  */
    /* JADX WARN: Removed duplicated region for block: B:220:0x0665  */
    /* JADX WARN: Removed duplicated region for block: B:223:0x066e  */
    /* JADX WARN: Removed duplicated region for block: B:224:0x0672  */
    /* JADX WARN: Removed duplicated region for block: B:231:0x068e  */
    /* JADX WARN: Removed duplicated region for block: B:51:0x0283  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x001c  */
    /* JADX WARN: Removed duplicated region for block: B:88:0x0361 A[Catch: all -> 0x038c, TRY_LEAVE, TryCatch #8 {all -> 0x038c, blocks: (B:86:0x0349, B:88:0x0361), top: B:254:0x0349 }] */
    /* JADX WARN: Removed duplicated region for block: B:97:0x038e  */
    /* JADX WARN: Type inference failed for: r0v11, types: [kotlinx.coroutines.sync.a] */
    /* JADX WARN: Type inference failed for: r1v31, types: [kotlinx.coroutines.sync.a] */
    /* JADX WARN: Type inference failed for: r1v4, types: [java.lang.Enum, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r1v8 */
    /* JADX WARN: Type inference failed for: r1v95 */
    /* JADX WARN: Type inference failed for: r6v1, types: [java.lang.Object, kotlinx.coroutines.sync.c] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(androidx.paging.C1336q0 r22, androidx.paging.G r23, androidx.paging.C1350y r24, kotlin.coroutines.h r25) {
        /*
            Method dump skipped, instructions count: 1730
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1336q0.b(androidx.paging.q0, androidx.paging.G, androidx.paging.y, kotlin.coroutines.h):java.lang.Object");
    }

    public static final Object c(C1336q0 c1336q0, G loadType, k1 viewportHint, C1322j0 c1322j0) throws Throwable {
        c1336q0.getClass();
        if (W.a[loadType.ordinal()] == 1) {
            Object objF = c1336q0.f(c1322j0);
            return objF == kotlin.coroutines.intrinsics.a.a ? objF : Unit.a;
        }
        if (viewportHint == null) {
            throw new IllegalStateException("Cannot retry APPEND / PREPEND load on PagingSource without ViewportHint");
        }
        com.google.android.gms.internal.instantapps.a aVar = c1336q0.e;
        aVar.getClass();
        Intrinsics.checkNotNullParameter(loadType, "loadType");
        Intrinsics.checkNotNullParameter(viewportHint, "viewportHint");
        if (loadType == G.b || loadType == G.c) {
            ((com.quizlet.data.repository.studysetwithcreator.d) aVar.b).c(null, new androidx.compose.foundation.contextmenu.i(28, loadType, viewportHint));
            return Unit.a;
        }
        throw new IllegalArgumentException(("invalid load type for reset: " + loadType).toString());
    }

    public static final void d(C1336q0 c1336q0, kotlinx.coroutines.C c) {
        C0676l1 c0676l1 = c1336q0.c;
        kotlinx.coroutines.E.A(c, null, null, new C1332o0(c1336q0, null), 3);
        kotlinx.coroutines.E.A(c, null, null, new C1334p0(c1336q0, null), 3);
    }

    public static String h(G g, Object obj, Q0 q0) {
        if (q0 == null) {
            return "End " + g + " with loadkey " + obj + ". Load CANCELLED.";
        }
        return "End " + g + " with loadKey " + obj + ". Returned " + q0;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object e(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof androidx.paging.C1308c0
            if (r0 == 0) goto L13
            r0 = r5
            androidx.paging.c0 r0 = (androidx.paging.C1308c0) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            androidx.paging.c0 r0 = new androidx.paging.c0
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            kotlinx.coroutines.sync.c r1 = r0.l
            androidx.paging.r0 r2 = r0.k
            androidx.paging.q0 r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L4d
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            androidx.paging.r0 r2 = r4.h
            kotlinx.coroutines.sync.c r5 = r2.a
            r0.j = r4
            r0.k = r2
            r0.l = r5
            r0.o = r3
            java.lang.Object r0 = r5.d(r0)
            if (r0 != r1) goto L4b
            return r1
        L4b:
            r0 = r4
            r1 = r5
        L4d:
            r5 = 0
            androidx.paging.u0 r2 = r2.b     // Catch: java.lang.Throwable -> L62
            com.google.android.gms.internal.instantapps.a r0 = r0.e     // Catch: java.lang.Throwable -> L62
            java.lang.Object r0 = r0.b     // Catch: java.lang.Throwable -> L62
            com.quizlet.data.repository.studysetwithcreator.d r0 = (com.quizlet.data.repository.studysetwithcreator.d) r0     // Catch: java.lang.Throwable -> L62
            java.lang.Object r0 = r0.c     // Catch: java.lang.Throwable -> L62
            androidx.paging.i1 r0 = (androidx.paging.i1) r0     // Catch: java.lang.Throwable -> L62
            androidx.paging.T0 r0 = r2.a(r0)     // Catch: java.lang.Throwable -> L62
            r1.f(r5)
            return r0
        L62:
            r0 = move-exception
            r1.f(r5)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1336q0.e(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:106:0x0232  */
    /* JADX WARN: Removed duplicated region for block: B:120:0x0282  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x011b  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x011d  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0136  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x013b  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0164  */
    /* JADX WARN: Removed duplicated region for block: B:62:0x016b  */
    /* JADX WARN: Removed duplicated region for block: B:71:0x01a0 A[Catch: all -> 0x01a4, TRY_ENTER, TryCatch #1 {all -> 0x01a4, blocks: (B:66:0x0186, B:68:0x0192, B:71:0x01a0, B:74:0x01a7, B:76:0x01ae), top: B:135:0x0186 }] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x01ae A[Catch: all -> 0x01a4, TRY_LEAVE, TryCatch #1 {all -> 0x01a4, blocks: (B:66:0x0186, B:68:0x0192, B:71:0x01a0, B:74:0x01a7, B:76:0x01ae), top: B:135:0x0186 }] */
    /* JADX WARN: Removed duplicated region for block: B:79:0x01b6  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0017  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x0202  */
    /* JADX WARN: Removed duplicated region for block: B:98:0x0215  */
    /* JADX WARN: Type inference failed for: r4v0, types: [int] */
    /* JADX WARN: Type inference failed for: r4v1 */
    /* JADX WARN: Type inference failed for: r4v34 */
    /* JADX WARN: Type inference failed for: r4v35 */
    /* JADX WARN: Type inference failed for: r4v8 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(kotlin.coroutines.jvm.internal.c r17) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 696
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.paging.C1336q0.f(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final N0 g(G loadType, Object obj) {
        Intrinsics.checkNotNullParameter(loadType, "loadType");
        int iOrdinal = loadType.ordinal();
        if (iOrdinal == 0) {
            return new M0(obj);
        }
        if (iOrdinal == 1) {
            if (obj != null) {
                return new L0(obj);
            }
            throw new IllegalArgumentException("key cannot be null for prepend");
        }
        if (iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        if (obj != null) {
            return new K0(obj);
        }
        throw new IllegalArgumentException("key cannot be null for append");
    }

    public final Object i(C1343u0 c1343u0, G loadType, int i, int i2) {
        c1343u0.getClass();
        Intrinsics.checkNotNullParameter(loadType, "loadType");
        int iOrdinal = loadType.ordinal();
        if (iOrdinal == 0) {
            throw new IllegalArgumentException("Cannot get loadId for loadType: REFRESH");
        }
        if (iOrdinal != 1 && iOrdinal != 2) {
            throw new NoWhenBranchMatchedException();
        }
        if (i != 0 || (c1343u0.j.m(loadType) instanceof B) || i2 >= this.c.b) {
            return null;
        }
        G g = G.b;
        ArrayList arrayList = c1343u0.c;
        return loadType == g ? ((P0) CollectionsKt.L(arrayList)).b : ((P0) CollectionsKt.U(arrayList)).c;
    }

    public final Object j(C1343u0 c1343u0, G g, B b, kotlin.coroutines.jvm.internal.c cVar) {
        if (Intrinsics.b(c1343u0.j.m(g), b)) {
            return Unit.a;
        }
        io.ktor.client.plugins.api.d dVar = c1343u0.j;
        dVar.z(g, b);
        Object objS = this.g.s(new M(dVar.B(), null), cVar);
        return objS == kotlin.coroutines.intrinsics.a.a ? objS : Unit.a;
    }

    public final Object k(C1343u0 c1343u0, G g, kotlin.coroutines.jvm.internal.c cVar) {
        E eM = c1343u0.j.m(g);
        C c = C.b;
        if (Intrinsics.b(eM, c)) {
            return Unit.a;
        }
        io.ktor.client.plugins.api.d dVar = c1343u0.j;
        dVar.z(g, c);
        Object objS = this.g.s(new M(dVar.B(), null), cVar);
        return objS == kotlin.coroutines.intrinsics.a.a ? objS : Unit.a;
    }
}
