package com.google.firebase.sessions;

import kotlin.coroutines.CoroutineContext;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class U implements Q {
    public static final double f = Math.random();
    public static final /* synthetic */ int g = 0;
    public final com.google.firebase.h a;
    public final com.google.firebase.installations.d b;
    public final com.google.firebase.sessions.settings.j c;
    public final C3990l d;
    public final CoroutineContext e;

    public U(com.google.firebase.h firebaseApp, com.google.firebase.installations.d firebaseInstallations, com.google.firebase.sessions.settings.j sessionSettings, C3990l eventGDTLogger, CoroutineContext backgroundDispatcher) {
        Intrinsics.checkNotNullParameter(firebaseApp, "firebaseApp");
        Intrinsics.checkNotNullParameter(firebaseInstallations, "firebaseInstallations");
        Intrinsics.checkNotNullParameter(sessionSettings, "sessionSettings");
        Intrinsics.checkNotNullParameter(eventGDTLogger, "eventGDTLogger");
        Intrinsics.checkNotNullParameter(backgroundDispatcher, "backgroundDispatcher");
        this.a = firebaseApp;
        this.b = firebaseInstallations;
        this.c = sessionSettings;
        this.d = eventGDTLogger;
        this.e = backgroundDispatcher;
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.google.firebase.sessions.U r4, kotlin.coroutines.jvm.internal.c r5) {
        /*
            boolean r0 = r5 instanceof com.google.firebase.sessions.T
            if (r0 == 0) goto L13
            r0 = r5
            com.google.firebase.sessions.T r0 = (com.google.firebase.sessions.T) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.m = r1
            goto L18
        L13:
            com.google.firebase.sessions.T r0 = new com.google.firebase.sessions.T
            r0.<init>(r4, r5)
        L18:
            java.lang.Object r5 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 1
            if (r2 == 0) goto L31
            if (r2 != r3) goto L29
            com.google.firebase.sessions.U r4 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r5)
            goto L41
        L29:
            java.lang.IllegalStateException r4 = new java.lang.IllegalStateException
            java.lang.String r5 = "call to 'resume' before 'invoke' with coroutine"
            r4.<init>(r5)
            throw r4
        L31:
            androidx.glance.appwidget.protobuf.Z.e(r5)
            r0.j = r4
            r0.m = r3
            com.google.firebase.sessions.settings.j r5 = r4.c
            java.lang.Object r5 = r5.b(r0)
            if (r5 != r1) goto L41
            return r1
        L41:
            com.google.firebase.sessions.settings.j r5 = r4.c
            com.google.firebase.sessions.settings.o r0 = r5.a
            java.lang.Boolean r0 = r0.a()
            if (r0 == 0) goto L50
            boolean r3 = r0.booleanValue()
            goto L5c
        L50:
            com.google.firebase.sessions.settings.o r5 = r5.b
            java.lang.Boolean r5 = r5.a()
            if (r5 == 0) goto L5c
            boolean r3 = r5.booleanValue()
        L5c:
            if (r3 != 0) goto L61
            java.lang.Boolean r4 = java.lang.Boolean.FALSE
            return r4
        L61:
            com.google.firebase.sessions.settings.j r4 = r4.c
            double r4 = r4.a()
            double r0 = com.google.firebase.sessions.U.f
            int r4 = (r0 > r4 ? 1 : (r0 == r4 ? 0 : -1))
            if (r4 > 0) goto L70
            java.lang.Boolean r4 = java.lang.Boolean.TRUE
            return r4
        L70:
            java.lang.Boolean r4 = java.lang.Boolean.FALSE
            return r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.firebase.sessions.U.a(com.google.firebase.sessions.U, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }
}
