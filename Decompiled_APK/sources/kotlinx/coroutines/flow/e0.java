package kotlinx.coroutines.flow;

import androidx.datastore.core.C1087t;
import androidx.paging.C1306b0;
import androidx.paging.C1319i;
import com.android.billingclient.api.C1472a;
import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import kotlin.Unit;
import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.functions.Function2;
import kotlinx.coroutines.C5023i0;
import kotlinx.coroutines.InterfaceC5025j0;
import kotlinx.coroutines.flow.internal.AbstractC4994b;
import kotlinx.coroutines.flow.internal.C5001i;

/* loaded from: classes3.dex */
public abstract class e0 {
    public static final C1472a a = new C1472a("NO_VALUE", 2);
    public static final C1472a b = new C1472a("NONE", 2);
    public static final C1472a c = new C1472a("PENDING", 2);

    public static final d0 a(int i, int i2, kotlinx.coroutines.channels.a aVar) {
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "replay cannot be negative, but was ").toString());
        }
        if (i2 < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i2, "extraBufferCapacity cannot be negative, but was ").toString());
        }
        if (i <= 0 && i2 <= 0 && aVar != kotlinx.coroutines.channels.a.a) {
            throw new IllegalArgumentException(("replay or extraBufferCapacity must be positive with non-default onBufferOverflow strategy " + aVar).toString());
        }
        int i3 = i2 + i;
        if (i3 < 0) {
            i3 = SubsamplingScaleImageView.TILE_SIZE_AUTO;
        }
        return new d0(i, i3, aVar);
    }

    public static /* synthetic */ d0 b(int i, int i2, kotlinx.coroutines.channels.a aVar, int i3) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = 0;
        }
        if ((i3 & 4) != 0) {
            aVar = kotlinx.coroutines.channels.a.a;
        }
        return a(i, i2, aVar);
    }

    public static final s0 c(Object obj) {
        if (obj == null) {
            obj = AbstractC4994b.b;
        }
        return new s0(obj);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object d(kotlinx.coroutines.flow.y0 r4, kotlin.jvm.functions.c r5, java.lang.Throwable r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            boolean r0 = r7 instanceof kotlinx.coroutines.flow.C5011t
            if (r0 == 0) goto L13
            r0 = r7
            kotlinx.coroutines.flow.t r0 = (kotlinx.coroutines.flow.C5011t) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.t r0 = new kotlinx.coroutines.flow.t
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            java.lang.Throwable r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L29
            goto L41
        L29:
            r4 = move-exception
            goto L44
        L2b:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            r0.j = r6     // Catch: java.lang.Throwable -> L29
            r0.l = r3     // Catch: java.lang.Throwable -> L29
            java.lang.Object r4 = r5.invoke(r4, r6, r0)     // Catch: java.lang.Throwable -> L29
            if (r4 != r1) goto L41
            return r1
        L41:
            kotlin.Unit r4 = kotlin.Unit.a
            return r4
        L44:
            if (r6 == 0) goto L4b
            if (r6 == r4) goto L4b
            kotlin.C4937f.a(r4, r6)
        L4b:
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.e0.d(kotlinx.coroutines.flow.y0, kotlin.jvm.functions.c, java.lang.Throwable, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final void e(Object[] objArr, long j, Object obj) {
        objArr[((int) j) & (objArr.length - 1)] = obj;
    }

    public static InterfaceC4992i f(InterfaceC4992i interfaceC4992i, int i) {
        kotlinx.coroutines.channels.a aVar = kotlinx.coroutines.channels.a.a;
        if (i < 0 && i != -2 && i != -1) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Buffer size should be non-negative, BUFFERED, or CONFLATED, but was ").toString());
        }
        if (i == -1) {
            aVar = kotlinx.coroutines.channels.a.b;
            i = 0;
        }
        int i2 = i;
        kotlinx.coroutines.channels.a aVar2 = aVar;
        return interfaceC4992i instanceof kotlinx.coroutines.flow.internal.z ? AbstractC4994b.b((kotlinx.coroutines.flow.internal.z) interfaceC4992i, null, i2, aVar2, 1) : new C5001i(interfaceC4992i, null, i2, aVar2, 2);
    }

    public static final C4986c g(Function2 function2) {
        return new C4986c(function2, kotlin.coroutines.n.a, -2, kotlinx.coroutines.channels.a.a);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.io.Serializable h(kotlinx.coroutines.flow.InterfaceC4992i r5, kotlinx.coroutines.flow.InterfaceC5002j r6, kotlin.coroutines.jvm.internal.c r7) throws java.lang.Throwable {
        /*
            boolean r0 = r7 instanceof kotlinx.coroutines.flow.C5016y
            if (r0 == 0) goto L13
            r0 = r7
            kotlinx.coroutines.flow.y r0 = (kotlinx.coroutines.flow.C5016y) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.y r0 = new kotlinx.coroutines.flow.y
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            kotlin.jvm.internal.J r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: java.lang.Throwable -> L29
            goto L4d
        L29:
            r6 = move-exception
            goto L51
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.jvm.internal.J r7 = new kotlin.jvm.internal.J
            r7.<init>()
            androidx.compose.foundation.text.i0 r2 = new androidx.compose.foundation.text.i0     // Catch: java.lang.Throwable -> L4f
            r4 = 28
            r2.<init>(r4, r6, r7)     // Catch: java.lang.Throwable -> L4f
            r0.j = r7     // Catch: java.lang.Throwable -> L4f
            r0.l = r3     // Catch: java.lang.Throwable -> L4f
            java.lang.Object r5 = r5.b(r2, r0)     // Catch: java.lang.Throwable -> L4f
            if (r5 != r1) goto L4d
            return r1
        L4d:
            r5 = 0
            return r5
        L4f:
            r6 = move-exception
            r5 = r7
        L51:
            java.lang.Object r5 = r5.a
            java.lang.Throwable r5 = (java.lang.Throwable) r5
            if (r5 == 0) goto L5d
            boolean r7 = r5.equals(r6)
            if (r7 != 0) goto L7f
        L5d:
            kotlin.coroutines.CoroutineContext r7 = r0.getContext()
            kotlinx.coroutines.i0 r0 = kotlinx.coroutines.C5023i0.a
            kotlin.coroutines.CoroutineContext$Element r7 = r7.get(r0)
            kotlinx.coroutines.j0 r7 = (kotlinx.coroutines.InterfaceC5025j0) r7
            if (r7 == 0) goto L80
            boolean r0 = r7.isCancelled()
            if (r0 != 0) goto L72
            goto L80
        L72:
            java.util.concurrent.CancellationException r7 = r7.y()
            if (r7 == 0) goto L80
            boolean r7 = r7.equals(r6)
            if (r7 != 0) goto L7f
            goto L80
        L7f:
            throw r6
        L80:
            if (r5 != 0) goto L83
            return r6
        L83:
            boolean r7 = r6 instanceof java.util.concurrent.CancellationException
            if (r7 == 0) goto L8b
            kotlin.C4937f.a(r5, r6)
            throw r5
        L8b:
            kotlin.C4937f.a(r6, r5)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.e0.h(kotlinx.coroutines.flow.i, kotlinx.coroutines.flow.j, kotlin.coroutines.jvm.internal.c):java.io.Serializable");
    }

    public static final Object i(InterfaceC4992i interfaceC4992i, Function2 function2, kotlin.coroutines.h hVar) {
        int i = G.a;
        Object objB = f(new kotlinx.coroutines.flow.internal.m(new C1319i(function2, (kotlin.coroutines.h) null, 13), interfaceC4992i, kotlin.coroutines.n.a, -2, kotlinx.coroutines.channels.a.a), 0).b(kotlinx.coroutines.flow.internal.B.a, hVar);
        kotlin.coroutines.intrinsics.a aVar = kotlin.coroutines.intrinsics.a.a;
        if (objB != aVar) {
            objB = Unit.a;
        }
        return objB == aVar ? objB : Unit.a;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x0030  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final com.google.android.gms.cloudmessaging.k j(kotlinx.coroutines.flow.InterfaceC4992i r7, int r8) {
        /*
            kotlinx.coroutines.channels.k r0 = kotlinx.coroutines.channels.l.b1
            r0.getClass()
            int r0 = kotlinx.coroutines.channels.k.b
            if (r8 >= r0) goto La
            goto Lb
        La:
            r0 = r8
        Lb:
            int r0 = r0 - r8
            boolean r1 = r7 instanceof kotlinx.coroutines.flow.internal.AbstractC4998f
            if (r1 == 0) goto L3b
            r1 = r7
            kotlinx.coroutines.flow.internal.f r1 = (kotlinx.coroutines.flow.internal.AbstractC4998f) r1
            kotlinx.coroutines.flow.i r2 = r1.i()
            if (r2 == 0) goto L3b
            com.google.android.gms.cloudmessaging.k r7 = new com.google.android.gms.cloudmessaging.k
            r3 = -3
            kotlinx.coroutines.channels.a r4 = r1.c
            int r5 = r1.b
            if (r5 == r3) goto L29
            r3 = -2
            if (r5 == r3) goto L29
            if (r5 == 0) goto L29
            r0 = r5
            goto L35
        L29:
            kotlinx.coroutines.channels.a r3 = kotlinx.coroutines.channels.a.a
            r6 = 0
            if (r4 != r3) goto L32
            if (r5 != 0) goto L35
        L30:
            r0 = r6
            goto L35
        L32:
            if (r8 != 0) goto L30
            r0 = 1
        L35:
            kotlin.coroutines.CoroutineContext r8 = r1.a
            r7.<init>(r0, r8, r4, r2)
            return r7
        L3b:
            com.google.android.gms.cloudmessaging.k r8 = new com.google.android.gms.cloudmessaging.k
            kotlinx.coroutines.channels.a r1 = kotlinx.coroutines.channels.a.a
            kotlin.coroutines.n r2 = kotlin.coroutines.n.a
            r8.<init>(r0, r2, r1, r7)
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.e0.j(kotlinx.coroutines.flow.i, int):com.google.android.gms.cloudmessaging.k");
    }

    public static final C4987d k(kotlinx.coroutines.channels.h hVar) {
        return new C4987d(hVar, true);
    }

    public static final InterfaceC4992i l(InterfaceC4992i interfaceC4992i, long j) {
        if (j >= 0) {
            return j == 0 ? interfaceC4992i : new C1087t(new C5010s(new com.braze.requests.framework.m(28, j), interfaceC4992i, null), 12);
        }
        throw new IllegalArgumentException("Debounce timeout should not be negative");
    }

    public static final InterfaceC4992i m(InterfaceC4992i interfaceC4992i) {
        if (interfaceC4992i instanceof q0) {
            return interfaceC4992i;
        }
        if (!(interfaceC4992i instanceof C4990g)) {
            return new C4990g(interfaceC4992i);
        }
        ((C4990g) interfaceC4992i).getClass();
        return interfaceC4992i;
    }

    public static final C1306b0 n(InterfaceC4992i interfaceC4992i, int i) {
        if (i >= 0) {
            return new C1306b0(interfaceC4992i, i, 1);
        }
        throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "Drop count should be non-negative, but had ").toString());
    }

    /* JADX WARN: Code restructure failed: missing block: B:32:0x0084, code lost:
    
        if (r2.emit(r9, r0) == r1) goto L33;
     */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0065  */
    /* JADX WARN: Removed duplicated region for block: B:28:0x0066  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0072 A[Catch: all -> 0x0034, TRY_LEAVE, TryCatch #1 {all -> 0x0034, blocks: (B:13:0x002e, B:25:0x0055, B:29:0x006a, B:31:0x0072, B:20:0x0046, B:24:0x0051), top: B:47:0x0020 }] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Unsupported multi-entry loop pattern (BACK_EDGE: B:32:0x0084 -> B:14:0x0031). Please report as a decompilation issue!!! */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object o(kotlinx.coroutines.flow.InterfaceC5002j r6, kotlinx.coroutines.channels.w r7, boolean r8, kotlin.coroutines.h r9) throws java.lang.Throwable {
        /*
            boolean r0 = r9 instanceof kotlinx.coroutines.flow.C5004l
            if (r0 == 0) goto L13
            r0 = r9
            kotlinx.coroutines.flow.l r0 = (kotlinx.coroutines.flow.C5004l) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.l r0 = new kotlinx.coroutines.flow.l
            r0.<init>(r9)
        L18:
            java.lang.Object r9 = r0.n
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L4a
            if (r2 == r4) goto L3e
            if (r2 != r3) goto L36
            boolean r8 = r0.m
            kotlinx.coroutines.channels.c r6 = r0.l
            kotlinx.coroutines.channels.w r7 = r0.k
            kotlinx.coroutines.flow.j r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L34
        L31:
            r9 = r6
            r6 = r2
            goto L55
        L34:
            r6 = move-exception
            goto L90
        L36:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L3e:
            boolean r8 = r0.m
            kotlinx.coroutines.channels.c r6 = r0.l
            kotlinx.coroutines.channels.w r7 = r0.k
            kotlinx.coroutines.flow.j r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r9)     // Catch: java.lang.Throwable -> L34
            goto L6a
        L4a:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            boolean r9 = r6 instanceof kotlinx.coroutines.flow.y0
            if (r9 != 0) goto L98
            kotlinx.coroutines.channels.c r9 = r7.iterator()     // Catch: java.lang.Throwable -> L34
        L55:
            r0.j = r6     // Catch: java.lang.Throwable -> L34
            r0.k = r7     // Catch: java.lang.Throwable -> L34
            r0.l = r9     // Catch: java.lang.Throwable -> L34
            r0.m = r8     // Catch: java.lang.Throwable -> L34
            r0.o = r4     // Catch: java.lang.Throwable -> L34
            java.lang.Object r2 = r9.b(r0)     // Catch: java.lang.Throwable -> L34
            if (r2 != r1) goto L66
            goto L86
        L66:
            r5 = r2
            r2 = r6
            r6 = r9
            r9 = r5
        L6a:
            java.lang.Boolean r9 = (java.lang.Boolean) r9     // Catch: java.lang.Throwable -> L34
            boolean r9 = r9.booleanValue()     // Catch: java.lang.Throwable -> L34
            if (r9 == 0) goto L87
            java.lang.Object r9 = r6.c()     // Catch: java.lang.Throwable -> L34
            r0.j = r2     // Catch: java.lang.Throwable -> L34
            r0.k = r7     // Catch: java.lang.Throwable -> L34
            r0.l = r6     // Catch: java.lang.Throwable -> L34
            r0.m = r8     // Catch: java.lang.Throwable -> L34
            r0.o = r3     // Catch: java.lang.Throwable -> L34
            java.lang.Object r9 = r2.emit(r9, r0)     // Catch: java.lang.Throwable -> L34
            if (r9 != r1) goto L31
        L86:
            return r1
        L87:
            if (r8 == 0) goto L8d
            r6 = 0
            r7.j(r6)
        L8d:
            kotlin.Unit r6 = kotlin.Unit.a
            return r6
        L90:
            throw r6     // Catch: java.lang.Throwable -> L91
        L91:
            r9 = move-exception
            if (r8 == 0) goto L97
            com.google.android.gms.internal.mlkit_vision_camera.E1.a(r7, r6)
        L97:
            throw r9
        L98:
            kotlinx.coroutines.flow.y0 r6 = (kotlinx.coroutines.flow.y0) r6
            java.lang.Throwable r6 = r6.a
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.e0.o(kotlinx.coroutines.flow.j, kotlinx.coroutines.channels.w, boolean, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x005e  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0069 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x006a  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0072  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object p(kotlinx.coroutines.flow.InterfaceC4992i r6, kotlin.coroutines.h r7) {
        /*
            boolean r0 = r7 instanceof kotlinx.coroutines.flow.J
            if (r0 == 0) goto L13
            r0 = r7
            kotlinx.coroutines.flow.J r0 = (kotlinx.coroutines.flow.J) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.J r0 = new kotlinx.coroutines.flow.J
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            com.android.billingclient.api.a r3 = kotlinx.coroutines.flow.internal.AbstractC4994b.b
            r4 = 1
            if (r2 == 0) goto L37
            if (r2 != r4) goto L2f
            kotlinx.coroutines.flow.H r6 = r0.k
            kotlin.jvm.internal.J r1 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L2d
            goto L65
        L2d:
            r7 = move-exception
            goto L5a
        L2f:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.jvm.internal.J r7 = new kotlin.jvm.internal.J
            r7.<init>()
            r7.a = r3
            kotlinx.coroutines.flow.H r2 = new kotlinx.coroutines.flow.H
            r5 = 0
            r2.<init>(r7, r5)
            r0.j = r7     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L56
            r0.k = r2     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L56
            r0.m = r4     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L56
            java.lang.Object r6 = r6.b(r2, r0)     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L56
            if (r6 != r1) goto L54
            return r1
        L54:
            r1 = r7
            goto L65
        L56:
            r6 = move-exception
            r1 = r7
            r7 = r6
            r6 = r2
        L5a:
            java.lang.Object r2 = r7.a
            if (r2 != r6) goto L72
            kotlin.coroutines.CoroutineContext r6 = r0.getContext()
            kotlinx.coroutines.E.o(r6)
        L65:
            java.lang.Object r6 = r1.a
            if (r6 == r3) goto L6a
            return r6
        L6a:
            java.util.NoSuchElementException r6 = new java.util.NoSuchElementException
            java.lang.String r7 = "Expected at least one element"
            r6.<init>(r7)
            throw r6
        L72:
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.e0.p(kotlinx.coroutines.flow.i, kotlin.coroutines.h):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x005d  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0068 A[RETURN] */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0069  */
    /* JADX WARN: Removed duplicated region for block: B:33:0x0071  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object q(kotlinx.coroutines.flow.InterfaceC4992i r5, kotlin.jvm.functions.Function2 r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            boolean r0 = r7 instanceof kotlinx.coroutines.flow.K
            if (r0 == 0) goto L13
            r0 = r7
            kotlinx.coroutines.flow.K r0 = (kotlinx.coroutines.flow.K) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.K r0 = new kotlinx.coroutines.flow.K
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            com.android.billingclient.api.a r3 = kotlinx.coroutines.flow.internal.AbstractC4994b.b
            r4 = 1
            if (r2 == 0) goto L37
            if (r2 != r4) goto L2f
            kotlinx.coroutines.flow.l0 r5 = r0.k
            kotlin.jvm.internal.J r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L2d
            goto L64
        L2d:
            r7 = move-exception
            goto L59
        L2f:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L37:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.jvm.internal.J r7 = new kotlin.jvm.internal.J
            r7.<init>()
            r7.a = r3
            kotlinx.coroutines.flow.l0 r2 = new kotlinx.coroutines.flow.l0
            r2.<init>(r6, r7)
            r0.j = r7     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L55
            r0.k = r2     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L55
            r0.m = r4     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L55
            java.lang.Object r5 = r5.b(r2, r0)     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L55
            if (r5 != r1) goto L53
            return r1
        L53:
            r6 = r7
            goto L64
        L55:
            r5 = move-exception
            r6 = r7
            r7 = r5
            r5 = r2
        L59:
            java.lang.Object r1 = r7.a
            if (r1 != r5) goto L71
            kotlin.coroutines.CoroutineContext r5 = r0.getContext()
            kotlinx.coroutines.E.o(r5)
        L64:
            java.lang.Object r5 = r6.a
            if (r5 == r3) goto L69
            return r5
        L69:
            java.util.NoSuchElementException r5 = new java.util.NoSuchElementException
            java.lang.String r6 = "Expected at least one element matching the predicate"
            r5.<init>(r6)
            throw r5
        L71:
            throw r7
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.e0.q(kotlinx.coroutines.flow.i, kotlin.jvm.functions.Function2, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:27:0x005a  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x0064  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object r(kotlinx.coroutines.flow.InterfaceC4992i r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof kotlinx.coroutines.flow.L
            if (r0 == 0) goto L13
            r0 = r6
            kotlinx.coroutines.flow.L r0 = (kotlinx.coroutines.flow.L) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.L r0 = new kotlinx.coroutines.flow.L
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L35
            if (r2 != r3) goto L2d
            kotlinx.coroutines.flow.H r5 = r0.k
            kotlin.jvm.internal.J r1 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L2b
            goto L61
        L2b:
            r6 = move-exception
            goto L56
        L2d:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L35:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.jvm.internal.J r6 = new kotlin.jvm.internal.J
            r6.<init>()
            kotlinx.coroutines.flow.H r2 = new kotlinx.coroutines.flow.H
            r4 = 1
            r2.<init>(r6, r4)
            r0.j = r6     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L52
            r0.k = r2     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L52
            r0.m = r3     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L52
            java.lang.Object r5 = r5.b(r2, r0)     // Catch: kotlinx.coroutines.flow.internal.AbortFlowException -> L52
            if (r5 != r1) goto L50
            return r1
        L50:
            r1 = r6
            goto L61
        L52:
            r5 = move-exception
            r1 = r6
            r6 = r5
            r5 = r2
        L56:
            java.lang.Object r2 = r6.a
            if (r2 != r5) goto L64
            kotlin.coroutines.CoroutineContext r5 = r0.getContext()
            kotlinx.coroutines.E.o(r5)
        L61:
            java.lang.Object r5 = r1.a
            return r5
        L64:
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.e0.r(kotlinx.coroutines.flow.i, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final InterfaceC4992i s(InterfaceC4992i interfaceC4992i, CoroutineContext coroutineContext) {
        if (coroutineContext.get(C5023i0.a) == null) {
            return coroutineContext.equals(kotlin.coroutines.n.a) ? interfaceC4992i : interfaceC4992i instanceof kotlinx.coroutines.flow.internal.z ? AbstractC4994b.b((kotlinx.coroutines.flow.internal.z) interfaceC4992i, coroutineContext, 0, null, 6) : new C5001i(interfaceC4992i, coroutineContext, 0, null, 12);
        }
        throw new IllegalArgumentException(("Flow context cannot contain job in it. Had " + coroutineContext).toString());
    }

    public static final InterfaceC4992i t(a0 a0Var, CoroutineContext coroutineContext, int i, kotlinx.coroutines.channels.a aVar) {
        return ((i == 0 || i == -3) && aVar == kotlinx.coroutines.channels.a.a) ? a0Var : new C5001i(i, coroutineContext, aVar, a0Var);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object u(kotlinx.coroutines.flow.InterfaceC4992i r6, kotlin.coroutines.jvm.internal.c r7) {
        /*
            boolean r0 = r7 instanceof kotlinx.coroutines.flow.M
            if (r0 == 0) goto L13
            r0 = r7
            kotlinx.coroutines.flow.M r0 = (kotlinx.coroutines.flow.M) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.M r0 = new kotlinx.coroutines.flow.M
            r0.<init>(r7)
        L18:
            java.lang.Object r7 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            com.android.billingclient.api.a r3 = kotlinx.coroutines.flow.internal.AbstractC4994b.b
            r4 = 1
            if (r2 == 0) goto L33
            if (r2 != r4) goto L2b
            kotlin.jvm.internal.J r6 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r7)
            goto L4f
        L2b:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r7 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r7)
            throw r6
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r7)
            kotlin.jvm.internal.J r7 = new kotlin.jvm.internal.J
            r7.<init>()
            r7.a = r3
            kotlinx.coroutines.flow.H r2 = new kotlinx.coroutines.flow.H
            r5 = 2
            r2.<init>(r7, r5)
            r0.j = r7
            r0.l = r4
            java.lang.Object r6 = r6.b(r2, r0)
            if (r6 != r1) goto L4e
            return r1
        L4e:
            r6 = r7
        L4f:
            java.lang.Object r6 = r6.a
            if (r6 == r3) goto L54
            return r6
        L54:
            java.util.NoSuchElementException r6 = new java.util.NoSuchElementException
            java.lang.String r7 = "Expected at least one element"
            r6.<init>(r7)
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.e0.u(kotlinx.coroutines.flow.i, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object v(androidx.paging.J0 r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            boolean r0 = r6 instanceof kotlinx.coroutines.flow.N
            if (r0 == 0) goto L13
            r0 = r6
            kotlinx.coroutines.flow.N r0 = (kotlinx.coroutines.flow.N) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            kotlinx.coroutines.flow.N r0 = new kotlinx.coroutines.flow.N
            r0.<init>(r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            kotlin.jvm.internal.J r5 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4b
        L29:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            kotlin.jvm.internal.J r6 = new kotlin.jvm.internal.J
            r6.<init>()
            kotlinx.coroutines.flow.H r2 = new kotlinx.coroutines.flow.H
            r4 = 3
            r2.<init>(r6, r4)
            r0.j = r6
            r0.l = r3
            java.lang.Object r5 = r5.b(r2, r0)
            if (r5 != r1) goto L4a
            return r1
        L4a:
            r5 = r6
        L4b:
            java.lang.Object r5 = r5.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: kotlinx.coroutines.flow.e0.v(androidx.paging.J0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final InterfaceC5025j0 w(InterfaceC4992i interfaceC4992i, kotlinx.coroutines.C c2) {
        return kotlinx.coroutines.E.A(c2, null, null, new C5005m(interfaceC4992i, null), 3);
    }

    public static final Z x(InterfaceC4992i interfaceC4992i, kotlinx.coroutines.C c2, i0 i0Var, Object obj) {
        com.google.android.gms.cloudmessaging.k kVarJ = j(interfaceC4992i, 1);
        s0 s0VarC = c(obj);
        InterfaceC4992i interfaceC4992i2 = (InterfaceC4992i) kVarJ.c;
        kotlinx.coroutines.E.z(c2, (CoroutineContext) kVarJ.e, i0Var.equals(h0.a) ? kotlinx.coroutines.D.a : kotlinx.coroutines.D.d, new Q(i0Var, interfaceC4992i2, s0VarC, obj, null));
        return new Z(s0VarC);
    }
}
