package androidx.datastore.core;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import com.google.android.gms.internal.mlkit_vision_camera.D1;
import java.util.List;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.flow.InterfaceC4992i;
import kotlinx.coroutines.y0;

/* loaded from: classes.dex */
public final class P implements InterfaceC1076h {
    public final m0 a;
    public final InterfaceC1070b b;
    public final kotlinx.coroutines.C c;
    public final C1087t d;
    public final kotlinx.coroutines.sync.c e;
    public int f;
    public y0 g;
    public final androidx.webkit.internal.p h;
    public final com.quizlet.data.repository.explanations.exercise.b i;
    public final kotlin.u j;
    public final kotlin.u k;
    public final com.quizlet.data.repository.explanations.question.a l;

    public P(m0 storage, List initTasksList, InterfaceC1070b corruptionHandler, kotlinx.coroutines.C scope) {
        Intrinsics.checkNotNullParameter(storage, "storage");
        Intrinsics.checkNotNullParameter(initTasksList, "initTasksList");
        Intrinsics.checkNotNullParameter(corruptionHandler, "corruptionHandler");
        Intrinsics.checkNotNullParameter(scope, "scope");
        this.a = storage;
        this.b = corruptionHandler;
        this.c = scope;
        this.d = new C1087t(new C1088u(this, null));
        this.e = kotlinx.coroutines.sync.d.a();
        this.h = new androidx.webkit.internal.p(9);
        this.i = new com.quizlet.data.repository.explanations.exercise.b(this, initTasksList);
        this.j = kotlin.l.b(new C1081m(this, 1));
        this.k = kotlin.l.b(new C1081m(this, 0));
        androidx.credentials.playservices.controllers.BeginSignIn.c onComplete = new androidx.credentials.playservices.controllers.BeginSignIn.c(this, 2);
        M consumeMessage = new M(this, null);
        L onUndeliveredElement = L.a;
        Intrinsics.checkNotNullParameter(scope, "scope");
        Intrinsics.checkNotNullParameter(onComplete, "onComplete");
        Intrinsics.checkNotNullParameter(onUndeliveredElement, "onUndeliveredElement");
        Intrinsics.checkNotNullParameter(consumeMessage, "consumeMessage");
        com.quizlet.data.repository.explanations.question.a aVar = new com.quizlet.data.repository.explanations.question.a();
        aVar.a = scope;
        aVar.b = consumeMessage;
        aVar.c = D1.a(SubsamplingScaleImageView.TILE_SIZE_AUTO, 6, null);
        aVar.d = new androidx.appcompat.app.Q(11);
        InterfaceC5025j0 interfaceC5025j0 = (InterfaceC5025j0) scope.getCoroutineContext().get(C5023i0.a);
        if (interfaceC5025j0 != null) {
            interfaceC5025j0.Q(new androidx.compose.ui.viewinterop.b(3, onComplete, aVar));
        }
        this.l = aVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object b(androidx.datastore.core.P r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4.getClass()
            boolean r0 = r5 instanceof androidx.datastore.core.C1089v
            if (r0 == 0) goto L16
            r0 = r5
            androidx.datastore.core.v r0 = (androidx.datastore.core.C1089v) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            androidx.datastore.core.v r0 = new androidx.datastore.core.v
            r0.<init>(r4, r5)
        L1b:
            java.lang.Object r5 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L38
            if (r2 != r3) goto L30
            kotlinx.coroutines.sync.c r4 = r0.k
            androidx.datastore.core.P r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r5 = r4
            r4 = r0
            goto L4a
        L30:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.j = r4
            kotlinx.coroutines.sync.c r5 = r4.e
            r0.k = r5
            r0.n = r3
            java.lang.Object r0 = r5.d(r0)
            if (r0 != r1) goto L4a
            return r1
        L4a:
            r0 = 0
            int r1 = r4.f     // Catch: java.lang.Throwable -> L5d
            int r1 = r1 + (-1)
            r4.f = r1     // Catch: java.lang.Throwable -> L5d
            if (r1 != 0) goto L5f
            kotlinx.coroutines.y0 r1 = r4.g     // Catch: java.lang.Throwable -> L5d
            if (r1 == 0) goto L5a
            r1.j(r0)     // Catch: java.lang.Throwable -> L5d
        L5a:
            r4.g = r0     // Catch: java.lang.Throwable -> L5d
            goto L5f
        L5d:
            r4 = move-exception
            goto L67
        L5f:
            kotlin.Unit r4 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L5d
            r5.f(r0)
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        L67:
            r5.f(r0)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.P.b(androidx.datastore.core.P, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Can't wrap try/catch for region: R(10:0|2|(2:4|(1:6)(1:7))(0)|8|(1:75)|(7:(1:(1:(1:13)(2:18|19))(3:20|21|22))(1:23)|14|52|65|(1:67)(1:68)|69|70)(5:24|77|25|(3:27|71|28)(3:38|(1:40)(1:41)|(2:43|(2:45|(1:47))(2:56|57))(2:58|(2:60|61)(2:62|63)))|51)|48|73|49|(1:(0))) */
    /* JADX WARN: Code restructure failed: missing block: B:29:0x007b, code lost:
    
        if (r9 == r1) goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x007e, code lost:
    
        r8 = r11;
        r11 = r9;
        r9 = r8;
     */
    /* JADX WARN: Code restructure failed: missing block: B:50:0x00bf, code lost:
    
        if (r9 == r1) goto L51;
     */
    /* JADX WARN: Code restructure failed: missing block: B:54:0x00c5, code lost:
    
        r9 = th;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:67:0x00ee  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /* JADX WARN: Type inference failed for: r9v0, types: [androidx.datastore.core.P, java.lang.Object] */
    /* JADX WARN: Type inference failed for: r9v1 */
    /* JADX WARN: Type inference failed for: r9v13 */
    /* JADX WARN: Type inference failed for: r9v16 */
    /* JADX WARN: Type inference failed for: r9v2 */
    /* JADX WARN: Type inference failed for: r9v20 */
    /* JADX WARN: Type inference failed for: r9v31 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object c(androidx.datastore.core.P r9, androidx.datastore.core.b0 r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            Method dump skipped, instructions count: 248
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.P.c(androidx.datastore.core.P, androidx.datastore.core.b0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object d(androidx.datastore.core.P r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4.getClass()
            boolean r0 = r5 instanceof androidx.datastore.core.C1092y
            if (r0 == 0) goto L16
            r0 = r5
            androidx.datastore.core.y r0 = (androidx.datastore.core.C1092y) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.n = r1
            goto L1b
        L16:
            androidx.datastore.core.y r0 = new androidx.datastore.core.y
            r0.<init>(r4, r5)
        L1b:
            java.lang.Object r5 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 1
            if (r2 == 0) goto L38
            if (r2 != r3) goto L30
            kotlinx.coroutines.sync.c r4 = r0.k
            androidx.datastore.core.P r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r5 = r4
            r4 = r0
            goto L4a
        L30:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.j = r4
            kotlinx.coroutines.sync.c r5 = r4.e
            r0.k = r5
            r0.n = r3
            java.lang.Object r0 = r5.d(r0)
            if (r0 != r1) goto L4a
            return r1
        L4a:
            r0 = 0
            int r1 = r4.f     // Catch: java.lang.Throwable -> L61
            int r1 = r1 + r3
            r4.f = r1     // Catch: java.lang.Throwable -> L61
            if (r1 != r3) goto L63
            kotlinx.coroutines.C r1 = r4.c     // Catch: java.lang.Throwable -> L61
            androidx.datastore.core.z r2 = new androidx.datastore.core.z     // Catch: java.lang.Throwable -> L61
            r2.<init>(r4, r0)     // Catch: java.lang.Throwable -> L61
            r3 = 3
            kotlinx.coroutines.y0 r1 = kotlinx.coroutines.E.A(r1, r0, r0, r2, r3)     // Catch: java.lang.Throwable -> L61
            r4.g = r1     // Catch: java.lang.Throwable -> L61
            goto L63
        L61:
            r4 = move-exception
            goto L6b
        L63:
            kotlin.Unit r4 = kotlin.Unit.a     // Catch: java.lang.Throwable -> L61
            r5.f(r0)
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        L6b:
            r5.f(r0)
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.P.d(androidx.datastore.core.P, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:45:0x00c6  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object e(androidx.datastore.core.P r8, boolean r9, kotlin.coroutines.h r10) throws java.lang.Throwable {
        /*
            Method dump skipped, instructions count: 212
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.P.e(androidx.datastore.core.P, boolean, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:40:0x00a2 A[Catch: CorruptionException -> 0x0062, TryCatch #2 {CorruptionException -> 0x0062, blocks: (B:19:0x005d, B:54:0x0101, B:24:0x006b, B:51:0x00e3, B:32:0x0088, B:40:0x00a2, B:42:0x00a8, B:36:0x0091, B:48:0x00d0), top: B:81:0x0023 }] */
    /* JADX WARN: Removed duplicated region for block: B:41:0x00a7  */
    /* JADX WARN: Removed duplicated region for block: B:45:0x00bf  */
    /* JADX WARN: Removed duplicated region for block: B:53:0x00ff  */
    /* JADX WARN: Removed duplicated region for block: B:63:0x013e A[Catch: all -> 0x016a, TryCatch #1 {all -> 0x016a, blocks: (B:61:0x012c, B:63:0x013e, B:64:0x0146), top: B:80:0x012c }] */
    /* JADX WARN: Removed duplicated region for block: B:64:0x0146 A[Catch: all -> 0x016a, TRY_LEAVE, TryCatch #1 {all -> 0x016a, blocks: (B:61:0x012c, B:63:0x013e, B:64:0x0146), top: B:80:0x012c }] */
    /* JADX WARN: Removed duplicated region for block: B:67:0x0156  */
    /* JADX WARN: Removed duplicated region for block: B:70:0x015e  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object f(androidx.datastore.core.P r9, boolean r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            Method dump skipped, instructions count: 386
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.P.f(androidx.datastore.core.P, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // androidx.datastore.core.InterfaceC1076h
    public final Object a(Function2 function2, kotlin.coroutines.h hVar) {
        r0 r0Var = (r0) hVar.getContext().get(q0.a);
        if (r0Var != null) {
            r0Var.b(this);
        }
        return kotlinx.coroutines.E.J(new r0(r0Var, this), new K(this, function2, null), hVar);
    }

    public final k0 g() {
        return (k0) this.k.getValue();
    }

    @Override // androidx.datastore.core.InterfaceC1076h
    public final InterfaceC4992i getData() {
        return this.d;
    }

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0063, code lost:
    
        if (r4.h(r0) == r1) goto L27;
     */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object h(kotlin.coroutines.jvm.internal.c r6) throws java.lang.Throwable {
        /*
            r5 = this;
            boolean r0 = r6 instanceof androidx.datastore.core.A
            if (r0 == 0) goto L13
            r0 = r6
            androidx.datastore.core.A r0 = (androidx.datastore.core.A) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            androidx.datastore.core.A r0 = new androidx.datastore.core.A
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L3e
            if (r2 == r4) goto L38
            if (r2 != r3) goto L30
            int r1 = r0.k
            androidx.datastore.core.P r0 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.lang.Throwable -> L2e
            goto L66
        L2e:
            r6 = move-exception
            goto L6f
        L30:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L38:
            androidx.datastore.core.P r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L51
        L3e:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            androidx.datastore.core.k0 r6 = r5.g()
            r0.j = r5
            r0.n = r4
            java.lang.Integer r6 = r6.a()
            if (r6 != r1) goto L50
            goto L65
        L50:
            r2 = r5
        L51:
            java.lang.Number r6 = (java.lang.Number) r6
            int r6 = r6.intValue()
            com.quizlet.data.repository.explanations.exercise.b r4 = r2.i     // Catch: java.lang.Throwable -> L6d
            r0.j = r2     // Catch: java.lang.Throwable -> L6d
            r0.k = r6     // Catch: java.lang.Throwable -> L6d
            r0.n = r3     // Catch: java.lang.Throwable -> L6d
            java.lang.Object r6 = r4.h(r0)     // Catch: java.lang.Throwable -> L6d
            if (r6 != r1) goto L66
        L65:
            return r1
        L66:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L69:
            r1 = r6
            r6 = r0
            r0 = r2
            goto L6f
        L6d:
            r0 = move-exception
            goto L69
        L6f:
            androidx.webkit.internal.p r0 = r0.h
            androidx.datastore.core.c0 r2 = new androidx.datastore.core.c0
            r2.<init>(r1, r6)
            r0.w(r2)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.P.h(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public final Object i(kotlin.coroutines.jvm.internal.c cVar) {
        return ((n0) this.j.getValue()).d(new C1085q(3, 1, null), cVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object j(java.lang.Object r11, boolean r12, kotlin.coroutines.jvm.internal.c r13) {
        /*
            r10 = this;
            boolean r0 = r13 instanceof androidx.datastore.core.N
            if (r0 == 0) goto L13
            r0 = r13
            androidx.datastore.core.N r0 = (androidx.datastore.core.N) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            androidx.datastore.core.N r0 = new androidx.datastore.core.N
            r0.<init>(r10, r13)
        L18:
            java.lang.Object r13 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            kotlin.jvm.internal.H r11 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r13)
            goto L56
        L29:
            java.lang.IllegalStateException r11 = new java.lang.IllegalStateException
            java.lang.String r12 = "call to 'resume' before 'invoke' with coroutine"
            r11.<init>(r12)
            throw r11
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r13)
            kotlin.jvm.internal.H r5 = new kotlin.jvm.internal.H
            r5.<init>()
            kotlin.u r13 = r10.j
            java.lang.Object r13 = r13.getValue()
            androidx.datastore.core.n0 r13 = (androidx.datastore.core.n0) r13
            androidx.datastore.core.O r4 = new androidx.datastore.core.O
            r9 = 0
            r6 = r10
            r7 = r11
            r8 = r12
            r4.<init>(r5, r6, r7, r8, r9)
            r0.j = r5
            r0.m = r3
            java.lang.Object r11 = r13.a(r4, r0)
            if (r11 != r1) goto L55
            return r1
        L55:
            r11 = r5
        L56:
            int r11 = r11.a
            java.lang.Integer r12 = new java.lang.Integer
            r12.<init>(r11)
            return r12
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.datastore.core.P.j(java.lang.Object, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
