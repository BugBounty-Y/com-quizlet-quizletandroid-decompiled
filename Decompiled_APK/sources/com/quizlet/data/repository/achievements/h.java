package com.quizlet.data.repository.achievements;

import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import androidx.compose.runtime.internal.j;
import androidx.work.impl.model.l;
import com.google.android.material.snackbar.i;
import com.quizlet.data.model.AbstractC4140k;
import com.quizlet.generated.enums.EnumC4467b;
import com.quizlet.generated.enums.EnumC4491j;
import kotlin.Unit;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.AbstractC5040y;
import kotlinx.coroutines.E;

/* loaded from: classes2.dex */
public final class h {
    public static h e;
    public Object a;
    public Object b;
    public Object c;
    public Object d;

    public /* synthetic */ h(Object obj, Object obj2, Object obj3, Object obj4) {
        this.a = obj;
        this.b = obj2;
        this.c = obj3;
        this.d = obj4;
    }

    public static h c() {
        if (e == null) {
            h hVar = new h();
            hVar.a = new Object();
            hVar.b = new Handler(Looper.getMainLooper(), new com.bumptech.glide.load.resource.gif.f(hVar, 2));
            e = hVar;
        }
        return e;
    }

    public boolean a(i iVar, int i) {
        com.google.android.material.snackbar.e eVar = (com.google.android.material.snackbar.e) iVar.a.get();
        if (eVar == null) {
            return false;
        }
        ((Handler) this.b).removeCallbacksAndMessages(iVar);
        Handler handler = com.google.android.material.snackbar.g.y;
        handler.sendMessage(handler.obtainMessage(1, i, 0, eVar.a));
        return true;
    }

    public Object b(kotlin.coroutines.jvm.internal.c cVar) {
        com.quizlet.local.cache.e eVar = ((com.quizlet.local.cache.caches.a) this.d).c;
        eVar.getClass();
        AbstractC4140k abstractC4140k = (AbstractC4140k) eVar.get(Unit.a);
        if (abstractC4140k != null) {
            return abstractC4140k;
        }
        return E.J((AbstractC5040y) this.c, new b(this, null), cVar);
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object d(java.lang.String r8, java.lang.String r9, com.quizlet.login.signup.data.PromptParentEmailData r10, kotlin.coroutines.jvm.internal.c r11) throws java.lang.Throwable {
        /*
            r7 = this;
            boolean r0 = r11 instanceof com.quizlet.login.common.interactors.y
            if (r0 == 0) goto L13
            r0 = r11
            com.quizlet.login.common.interactors.y r0 = (com.quizlet.login.common.interactors.y) r0
            int r1 = r0.n
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.n = r1
            goto L18
        L13:
            com.quizlet.login.common.interactors.y r0 = new com.quizlet.login.common.interactors.y
            r0.<init>(r7, r11)
        L18:
            java.lang.Object r11 = r0.l
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.n
            r3 = 2
            r4 = 0
            java.lang.String r5 = "email"
            r6 = 1
            if (r2 == 0) goto L3d
            if (r2 == r6) goto L35
            if (r2 != r3) goto L2d
            androidx.glance.appwidget.protobuf.Z.e(r11)
            return r11
        L2d:
            java.lang.IllegalStateException r8 = new java.lang.IllegalStateException
            java.lang.String r9 = "call to 'resume' before 'invoke' with coroutine"
            r8.<init>(r9)
            throw r8
        L35:
            java.lang.String r8 = r0.k
            com.quizlet.data.repository.achievements.h r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L88
        L3d:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            kotlin.jvm.internal.J r11 = new kotlin.jvm.internal.J
            r11.<init>()
            kotlin.collections.L r2 = kotlin.collections.V.c()
            r11.a = r2
            if (r10 == 0) goto L6a
            java.util.Map r10 = r10.a
            java.util.LinkedHashMap r10 = kotlin.collections.V.m(r10)
            r11.a = r10
            r10.put(r5, r8)
            java.lang.Object r10 = r11.a
            java.util.Map r10 = (java.util.Map) r10
            java.lang.String r2 = "password1"
            r10.put(r2, r9)
            java.lang.Object r10 = r11.a
            java.util.Map r10 = (java.util.Map) r10
            java.lang.String r2 = "password2"
            r10.put(r2, r9)
        L6a:
            java.lang.Object r9 = r7.b
            com.google.android.gms.internal.appset.e r9 = (com.google.android.gms.internal.appset.e) r9
            r9.r(r5, r6)
            com.quizlet.login.common.interactors.z r9 = new com.quizlet.login.common.interactors.z
            r9.<init>(r7, r11, r4)
            r0.j = r7
            r0.k = r8
            r0.n = r6
            java.lang.Object r10 = r7.c
            kotlinx.coroutines.y r10 = (kotlinx.coroutines.AbstractC5040y) r10
            java.lang.Object r11 = kotlinx.coroutines.E.J(r10, r9, r0)
            if (r11 != r1) goto L87
            goto L9f
        L87:
            r9 = r7
        L88:
            java.lang.String r10 = "withContext(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r11, r10)
            com.quizlet.login.authentication.data.i r11 = (com.quizlet.login.authentication.data.i) r11
            java.lang.Object r9 = r9.d
            androidx.compose.runtime.internal.j r9 = (androidx.compose.runtime.internal.j) r9
            r0.j = r4
            r0.k = r4
            r0.n = r3
            java.lang.Object r8 = r9.s(r11, r5, r8, r0)
            if (r8 != r1) goto La0
        L9f:
            return r1
        La0:
            return r8
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.achievements.h.d(java.lang.String, java.lang.String, com.quizlet.login.signup.data.PromptParentEmailData, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public boolean e(com.google.android.material.snackbar.e eVar) {
        i iVar = (i) this.c;
        return (iVar == null || eVar == null || iVar.a.get() != eVar) ? false : true;
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:31:0x0095  */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0097  */
    /* JADX WARN: Removed duplicated region for block: B:35:0x00a2  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00b0  */
    /* JADX WARN: Removed duplicated region for block: B:48:0x00d1  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /* JADX WARN: Type inference failed for: r7v17, types: [java.util.List] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public java.lang.Object f(int r6, java.util.ArrayList r7, kotlin.coroutines.jvm.internal.c r8) {
        /*
            Method dump skipped, instructions count: 237
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.data.repository.achievements.h.f(int, java.util.ArrayList, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    public void g(com.google.android.material.snackbar.e eVar) {
        synchronized (this.a) {
            try {
                if (e(eVar)) {
                    i iVar = (i) this.c;
                    if (!iVar.c) {
                        iVar.c = true;
                        ((Handler) this.b).removeCallbacksAndMessages(iVar);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public Object h(EnumC4491j enumC4491j, EnumC4467b enumC4467b, String str, kotlin.coroutines.jvm.internal.i iVar) throws Throwable {
        Object objJ = E.J((AbstractC5040y) this.c, new g(this, enumC4491j, enumC4467b, str, null), iVar);
        return objJ == kotlin.coroutines.intrinsics.a.a ? objJ : Unit.a;
    }

    public void i(com.google.android.material.snackbar.e eVar) {
        synchronized (this.a) {
            try {
                if (e(eVar)) {
                    i iVar = (i) this.c;
                    if (iVar.c) {
                        iVar.c = false;
                        j(iVar);
                    }
                }
            } catch (Throwable th) {
                throw th;
            }
        }
    }

    public void j(i iVar) {
        int i = iVar.b;
        if (i == -2) {
            return;
        }
        if (i <= 0) {
            i = i == -1 ? 1500 : 2750;
        }
        Handler handler = (Handler) this.b;
        handler.removeCallbacksAndMessages(iVar);
        handler.sendMessageDelayed(Message.obtain(handler, 0, iVar), i);
    }

    public void k() {
        i iVar = (i) this.d;
        if (iVar != null) {
            this.c = iVar;
            this.d = null;
            com.google.android.material.snackbar.e eVar = (com.google.android.material.snackbar.e) iVar.a.get();
            if (eVar == null) {
                this.c = null;
            } else {
                Handler handler = com.google.android.material.snackbar.g.y;
                handler.sendMessage(handler.obtainMessage(0, eVar.a));
            }
        }
    }

    public h(io.ktor.client.plugins.api.d apiClient, com.google.android.gms.internal.appset.e logger, com.quizlet.qutils.string.c state, com.quizlet.login.common.util.b ageUtil, com.quizlet.time.b timeUtils, com.google.firebase.heartbeatinfo.e getTeacherStatusUseCase, l signUpRequestParentEmailFeature, j handleLoginResponseUseCase, AbstractC5040y ioDispatcher) {
        Intrinsics.checkNotNullParameter(apiClient, "apiClient");
        Intrinsics.checkNotNullParameter(logger, "logger");
        Intrinsics.checkNotNullParameter(state, "state");
        Intrinsics.checkNotNullParameter(ageUtil, "ageUtil");
        Intrinsics.checkNotNullParameter(timeUtils, "timeUtils");
        Intrinsics.checkNotNullParameter(getTeacherStatusUseCase, "getTeacherStatusUseCase");
        Intrinsics.checkNotNullParameter(signUpRequestParentEmailFeature, "signUpRequestParentEmailFeature");
        Intrinsics.checkNotNullParameter(handleLoginResponseUseCase, "handleLoginResponseUseCase");
        Intrinsics.checkNotNullParameter(ioDispatcher, "ioDispatcher");
        this.a = apiClient;
        this.b = logger;
        this.d = handleLoginResponseUseCase;
        this.c = ioDispatcher;
    }
}
