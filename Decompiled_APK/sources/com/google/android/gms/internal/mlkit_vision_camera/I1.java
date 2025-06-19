package com.google.android.gms.internal.mlkit_vision_camera;

import androidx.navigation.C1265a;
import java.util.Iterator;
import java.util.NoSuchElementException;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlin.sequences.Sequence;
import kotlinx.coroutines.C5028l;

/* loaded from: classes2.dex */
public abstract class I1 {
    public static final /* synthetic */ int a = 0;

    public static final Object a(io.reactivex.rxjava3.core.a aVar, kotlin.coroutines.h frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        aVar.b(new androidx.credentials.c(c5028l));
        Object objQ = c5028l.q();
        kotlin.coroutines.intrinsics.a aVar2 = kotlin.coroutines.intrinsics.a.a;
        if (objQ == aVar2) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ == aVar2 ? objQ : Unit.a;
    }

    public static final Object b(io.reactivex.rxjava3.core.p pVar, kotlin.coroutines.h frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        pVar.j(new androidx.credentials.d(c5028l));
        Object objQ = c5028l.q();
        if (objQ == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }

    public static final Object c(io.reactivex.rxjava3.core.k kVar, kotlin.coroutines.h frame) {
        kotlinx.coroutines.rx3.a aVar = kotlinx.coroutines.rx3.a.b;
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        kVar.c(new kotlinx.coroutines.rx3.b(c5028l));
        Object objQ = c5028l.q();
        if (objQ == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object d(io.reactivex.rxjava3.internal.operators.maybe.h r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            boolean r0 = r5 instanceof kotlinx.coroutines.rx3.c
            if (r0 == 0) goto L13
            r0 = r5
            kotlinx.coroutines.rx3.c r0 = (kotlinx.coroutines.rx3.c) r0
            int r1 = r0.k
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.k = r1
            goto L18
        L13:
            kotlinx.coroutines.rx3.c r0 = new kotlinx.coroutines.rx3.c
            r0.<init>(r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.k
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L3b
        L27:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.k = r3
            java.lang.Object r5 = e(r4, r0)
            if (r5 != r1) goto L3b
            return r1
        L3b:
            if (r5 == 0) goto L3e
            return r5
        L3e:
            java.util.NoSuchElementException r4 = new java.util.NoSuchElementException
            r4.<init>()
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.mlkit_vision_camera.I1.d(io.reactivex.rxjava3.internal.operators.maybe.h, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public static final Object e(io.reactivex.rxjava3.internal.operators.maybe.h hVar, kotlin.coroutines.jvm.internal.c frame) {
        C5028l c5028l = new C5028l(1, kotlin.coroutines.intrinsics.h.b(frame));
        c5028l.r();
        hVar.e(new kotlinx.coroutines.rx3.d(c5028l));
        Object objQ = c5028l.q();
        if (objQ == kotlin.coroutines.intrinsics.a.a) {
            Intrinsics.checkNotNullParameter(frame, "frame");
        }
        return objQ;
    }

    public static androidx.navigation.B f(androidx.navigation.D d) {
        Intrinsics.checkNotNullParameter(d, "<this>");
        Intrinsics.checkNotNullParameter(d, "<this>");
        Sequence sequenceC = kotlin.sequences.n.c(new C1265a(8), d);
        Intrinsics.checkNotNullParameter(sequenceC, "<this>");
        Iterator it2 = sequenceC.iterator();
        if (!it2.hasNext()) {
            throw new NoSuchElementException("Sequence is empty.");
        }
        Object next = it2.next();
        while (it2.hasNext()) {
            next = it2.next();
        }
        return (androidx.navigation.B) next;
    }
}
