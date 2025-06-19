package com.google.android.gms.internal.ads;

import android.os.Handler;
import android.os.Looper;
import com.quizlet.data.exceptions.practicetests.PracticeTestNoInternetException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.concurrent.PriorityBlockingQueue;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public final class C3 {
    public Object a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public Object f;
    public Object g;
    public Object h;
    public Object i;
    public Object j;
    public Object k;

    public C3() {
        this.e = new androidx.navigation.internal.m();
        this.f = new androidx.navigation.internal.m();
        this.g = new androidx.navigation.internal.m();
        this.h = new androidx.navigation.internal.m();
        this.i = new androidx.navigation.internal.m();
        this.j = new com.quizlet.data.repository.user.e();
    }

    public void a() throws PracticeTestNoInternetException {
        if (!((com.quizlet.remote.connectivity.b) ((com.quizlet.data.connectivity.a) this.h)).a().a) {
            throw new PracticeTestNoInternetException();
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object b(kotlin.coroutines.jvm.internal.c r5) {
        /*
            r4 = this;
            boolean r0 = r5 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.C4695d
            if (r0 == 0) goto L13
            r0 = r5
            com.quizlet.quizletandroid.ui.startpage.nav2.d r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.C4695d) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.startpage.nav2.d r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.d
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L43
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r0)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.l = r3
            java.lang.Object r5 = r4.d
            com.quizlet.data.interactor.set.c r5 = (com.quizlet.data.interactor.set.c) r5
            java.lang.Object r5 = r5.a
            com.quizlet.data.repository.set.f r5 = (com.quizlet.data.repository.set.f) r5
            java.lang.Object r5 = r5.e(r0)
            if (r5 != r1) goto L43
            return r1
        L43:
            com.quizlet.data.model.s1 r5 = (com.quizlet.data.model.AbstractC4165s1) r5
            com.quizlet.quizletandroid.ui.startpage.nav2.model.t r5 = com.google.android.gms.internal.mlkit_vision_document_scanner.AbstractC3587b6.f(r5)
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C3.b(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object c(kotlin.coroutines.jvm.internal.c r6) {
        /*
            r5 = this;
            boolean r0 = r6 instanceof com.quizlet.quizletandroid.ui.startpage.nav2.C4696e
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.quizletandroid.ui.startpage.nav2.e r0 = (com.quizlet.quizletandroid.ui.startpage.nav2.C4696e) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.quizlet.quizletandroid.ui.startpage.nav2.e r0 = new com.quizlet.quizletandroid.ui.startpage.nav2.e
            r0.<init>(r5, r6)
        L18:
            java.lang.Object r6 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 2
            r4 = 1
            if (r2 == 0) goto L38
            if (r2 == r4) goto L32
            if (r2 != r3) goto L2a
            androidx.glance.appwidget.protobuf.Z.e(r6)
            return r6
        L2a:
            java.lang.IllegalStateException r6 = new java.lang.IllegalStateException
            java.lang.String r0 = "call to 'resume' before 'invoke' with coroutine"
            r6.<init>(r0)
            throw r6
        L32:
            com.google.android.gms.internal.ads.C3 r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r6)
            goto L4b
        L38:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            r0.j = r5
            r0.m = r4
            java.lang.Object r6 = r5.g
            com.google.firebase.crashlytics.internal.settings.b r6 = (com.google.firebase.crashlytics.internal.settings.b) r6
            java.lang.Object r6 = r6.h(r0)
            if (r6 != r1) goto L4a
            goto L6f
        L4a:
            r2 = r5
        L4b:
            java.lang.Boolean r6 = (java.lang.Boolean) r6
            boolean r6 = r6.booleanValue()
            if (r6 == 0) goto L71
            java.lang.Object r6 = r2.h
            com.onetrust.otpublishers.headless.UI.fragment.q r6 = (com.onetrust.otpublishers.headless.UI.fragment.q) r6
            r2 = 0
            r0.j = r2
            r0.m = r3
            java.lang.Object r6 = r6.b
            com.quizlet.remote.model.notes.e r6 = (com.quizlet.remote.model.notes.e) r6
            com.quizlet.remote.model.notes.b r3 = new com.quizlet.remote.model.notes.b
            r3.<init>(r6, r2)
            java.lang.Object r6 = r6.c
            kotlinx.coroutines.y r6 = (kotlinx.coroutines.AbstractC5040y) r6
            java.lang.Object r6 = kotlinx.coroutines.E.J(r6, r3, r0)
            if (r6 != r1) goto L70
        L6f:
            return r1
        L70:
            return r6
        L71:
            kotlin.collections.K r6 = kotlin.collections.K.a
            return r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C3.c(kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object d(java.lang.String r5, long r6, boolean r8, kotlin.coroutines.jvm.internal.c r9) throws com.quizlet.data.exceptions.practicetests.PracticeTestsException {
        /*
            r4 = this;
            boolean r0 = r9 instanceof com.quizlet.remote.model.practicetests.j
            if (r0 == 0) goto L13
            r0 = r9
            com.quizlet.remote.model.practicetests.j r0 = (com.quizlet.remote.model.practicetests.j) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.remote.model.practicetests.j r0 = new com.quizlet.remote.model.practicetests.j
            r0.<init>(r4, r9)
        L18:
            java.lang.Object r9 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L2f
            if (r2 != r3) goto L27
            androidx.glance.appwidget.protobuf.Z.e(r9)
            goto L4d
        L27:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L2f:
            androidx.glance.appwidget.protobuf.Z.e(r9)
            r4.a()
            com.quizlet.remote.model.practicetests.UpdateQuestionBankBody r9 = new com.quizlet.remote.model.practicetests.UpdateQuestionBankBody
            r9.<init>(r6, r8)
            java.lang.String r6 = "toString(...)"
            java.lang.String r6 = androidx.compose.ui.node.B.f(r6)
            r0.l = r3
            java.lang.Object r7 = r4.a
            com.quizlet.remote.service.r r7 = (com.quizlet.remote.service.r) r7
            java.lang.Object r9 = r7.i(r9, r5, r6, r0)
            if (r9 != r1) goto L4d
            return r1
        L4d:
            com.quizlet.remote.model.base.ApiThreeWrapper r9 = (com.quizlet.remote.model.base.ApiThreeWrapper) r9
            com.quizlet.remote.model.base.ApiResponse r5 = r9.a()
            com.quizlet.remote.model.practicetests.RemoteUpdateQuestionBankResponse r5 = (com.quizlet.remote.model.practicetests.RemoteUpdateQuestionBankResponse) r5
            if (r5 == 0) goto L6a
            com.quizlet.remote.model.practicetests.RemoteUpdateQuestionBankModel r5 = r5.d
            if (r5 == 0) goto L6a
            java.util.List r5 = r5.a
            if (r5 == 0) goto L6a
            java.lang.Object r5 = kotlin.collections.CollectionsKt.L(r5)
            com.quizlet.remote.model.practicetests.RemoteQuestionBankUuid r5 = (com.quizlet.remote.model.practicetests.RemoteQuestionBankUuid) r5
            if (r5 == 0) goto L6a
            java.lang.String r5 = r5.a
            goto L6b
        L6a:
            r5 = 0
        L6b:
            if (r5 == 0) goto L6e
            return r5
        L6e:
            com.quizlet.data.exceptions.practicetests.PracticeTestsException r5 = new com.quizlet.data.exceptions.practicetests.PracticeTestsException
            java.lang.String r6 = "Updated Question Id should not be null"
            r5.<init>(r6)
            throw r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C3.d(java.lang.String, long, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void e(B3 b3) {
        b3.h = this;
        HashSet hashSet = (HashSet) this.b;
        synchronized (hashSet) {
            hashSet.add(b3);
        }
        b3.g = Integer.valueOf(((AtomicInteger) this.a).incrementAndGet());
        b3.d("add-to-queue");
        f();
        ((PriorityBlockingQueue) this.c).add(b3);
    }

    public void f() {
        ArrayList arrayList = (ArrayList) this.j;
        synchronized (arrayList) {
            try {
                Iterator it2 = arrayList.iterator();
                if (it2.hasNext()) {
                    if (it2.next() != null) {
                        throw new ClassCastException();
                    }
                    throw null;
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void g() {
        C2726v3 c2726v3 = (C2726v3) this.h;
        if (c2726v3 != null) {
            c2726v3.d = true;
            c2726v3.interrupt();
        }
        C2898z3[] c2898z3Arr = (C2898z3[]) this.g;
        for (int i = 0; i < 4; i++) {
            C2898z3 c2898z3 = c2898z3Arr[i];
            if (c2898z3 != null) {
                c2898z3.d = true;
                c2898z3.interrupt();
            }
        }
        PriorityBlockingQueue priorityBlockingQueue = (PriorityBlockingQueue) this.c;
        PriorityBlockingQueue priorityBlockingQueue2 = (PriorityBlockingQueue) this.d;
        com.android.volley.toolbox.d dVar = (com.android.volley.toolbox.d) this.e;
        S4 s4 = (S4) this.k;
        C2726v3 c2726v32 = new C2726v3(priorityBlockingQueue, priorityBlockingQueue2, dVar, s4);
        this.h = c2726v32;
        c2726v32.start();
        for (int i2 = 0; i2 < 4; i2++) {
            C2898z3 c2898z32 = new C2898z3(priorityBlockingQueue2, (C1732Mb) this.f, dVar, s4);
            c2898z3Arr[i2] = c2898z32;
            c2898z32.start();
        }
    }

    public C3(com.android.volley.toolbox.d dVar, C1732Mb c1732Mb) {
        S4 s4 = new S4(new Handler(Looper.getMainLooper()));
        this.a = new AtomicInteger();
        this.b = new HashSet();
        this.c = new PriorityBlockingQueue();
        this.d = new PriorityBlockingQueue();
        this.i = new ArrayList();
        this.j = new ArrayList();
        this.e = dVar;
        this.f = c1732Mb;
        this.g = new C2898z3[4];
        this.k = s4;
    }
}
