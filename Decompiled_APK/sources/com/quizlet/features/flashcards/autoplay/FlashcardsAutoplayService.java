package com.quizlet.features.flashcards.autoplay;

import android.app.ForegroundServiceStartNotAllowedException;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import androidx.core.app.AbstractC1020g;
import androidx.core.app.C1034v;
import androidx.lifecycle.X;
import com.quizlet.quizletandroid.u;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import kotlinx.coroutines.E;
import kotlinx.coroutines.O;
import kotlinx.coroutines.y0;

@Metadata
/* loaded from: classes2.dex */
public final class FlashcardsAutoplayService extends Service implements dagger.hilt.internal.b {
    public static final /* synthetic */ int o = 0;
    public volatile dagger.hilt.android.internal.managers.i a;
    public final Object b = new Object();
    public boolean c = false;
    public a d;
    public com.quizlet.quizletandroid.managers.audio.h e;
    public C1034v f;
    public NotificationManager g;
    public kotlinx.coroutines.internal.d h;
    public X i;
    public com.quizlet.features.flashcards.engine.h j;
    public boolean k;
    public com.quizlet.features.flashcards.data.b l;
    public boolean m;
    public y0 n;

    /* JADX WARN: Code restructure failed: missing block: B:26:0x0069, code lost:
    
        if (r9.i(r0) == r1) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:41:0x008c, code lost:
    
        if (r9.c(r3, r10, r0) == r1) goto L42;
     */
    /* JADX WARN: Removed duplicated region for block: B:25:0x0061  */
    /* JADX WARN: Removed duplicated region for block: B:30:0x006f  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0016  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static final java.lang.Object a(com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService r9, com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3146g0 r10, kotlin.coroutines.jvm.internal.c r11) {
        /*
            r9.getClass()
            boolean r0 = r11 instanceof com.quizlet.features.flashcards.autoplay.j
            if (r0 == 0) goto L16
            r0 = r11
            com.quizlet.features.flashcards.autoplay.j r0 = (com.quizlet.features.flashcards.autoplay.j) r0
            int r1 = r0.m
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L16
            int r1 = r1 - r2
            r0.m = r1
            goto L1b
        L16:
            com.quizlet.features.flashcards.autoplay.j r0 = new com.quizlet.features.flashcards.autoplay.j
            r0.<init>(r9, r11)
        L1b:
            java.lang.Object r11 = r0.k
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.m
            r3 = 0
            r4 = 3
            r5 = 2
            r6 = 1
            if (r2 == 0) goto L43
            if (r2 == r6) goto L3d
            if (r2 == r5) goto L39
            if (r2 != r4) goto L31
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L8f
        L31:
            java.lang.IllegalStateException r9 = new java.lang.IllegalStateException
            java.lang.String r10 = "call to 'resume' before 'invoke' with coroutine"
            r9.<init>(r10)
            throw r9
        L39:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L6c
        L3d:
            com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService r9 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r11)
            goto L5d
        L43:
            androidx.glance.appwidget.protobuf.Z.e(r11)
            boolean r11 = r10 instanceof com.quizlet.features.flashcards.data.t
            if (r11 == 0) goto L72
            java.util.concurrent.TimeUnit r10 = java.util.concurrent.TimeUnit.SECONDS
            r7 = 1
            long r10 = r10.toMillis(r7)
            r0.j = r9
            r0.m = r6
            java.lang.Object r10 = kotlinx.coroutines.E.n(r10, r0)
            if (r10 != r1) goto L5d
            goto L8e
        L5d:
            com.quizlet.features.flashcards.engine.h r9 = r9.j
            if (r9 == 0) goto L6f
            r0.j = r3
            r0.m = r5
            java.lang.Object r9 = r9.i(r0)
            if (r9 != r1) goto L6c
            goto L8e
        L6c:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L6f:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        L72:
            boolean r11 = r10 instanceof com.quizlet.features.flashcards.data.b
            if (r11 != 0) goto L7f
            if (r10 != 0) goto L79
            goto L7f
        L79:
            kotlin.NoWhenBranchMatchedException r9 = new kotlin.NoWhenBranchMatchedException
            r9.<init>()
            throw r9
        L7f:
            if (r11 == 0) goto L84
            r3 = r10
            com.quizlet.features.flashcards.data.b r3 = (com.quizlet.features.flashcards.data.b) r3
        L84:
            boolean r10 = r9.m
            r0.m = r4
            java.lang.Object r9 = r9.c(r3, r10, r0)
            if (r9 != r1) goto L8f
        L8e:
            return r1
        L8f:
            kotlin.Unit r9 = kotlin.Unit.a
            return r9
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService.a(com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService, com.google.android.gms.internal.mlkit_vision_barcode.g0, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object b(java.lang.String r5, kotlin.coroutines.jvm.internal.c r6) {
        /*
            r4 = this;
            boolean r0 = r6 instanceof com.quizlet.features.flashcards.autoplay.h
            if (r0 == 0) goto L13
            r0 = r6
            com.quizlet.features.flashcards.autoplay.h r0 = (com.quizlet.features.flashcards.autoplay.h) r0
            int r1 = r0.l
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.l = r1
            goto L18
        L13:
            com.quizlet.features.flashcards.autoplay.h r0 = new com.quizlet.features.flashcards.autoplay.h
            r0.<init>(r4, r6)
        L18:
            java.lang.Object r6 = r0.j
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.l
            r3 = 1
            if (r2 == 0) goto L33
            if (r2 != r3) goto L2b
            androidx.glance.appwidget.protobuf.Z.e(r6)     // Catch: java.io.IOException -> L27 java.lang.IllegalStateException -> L29
            goto L59
        L27:
            r5 = move-exception
            goto L4e
        L29:
            r5 = move-exception
            goto L54
        L2b:
            java.lang.IllegalStateException r5 = new java.lang.IllegalStateException
            java.lang.String r6 = "call to 'resume' before 'invoke' with coroutine"
            r5.<init>(r6)
            throw r5
        L33:
            androidx.glance.appwidget.protobuf.Z.e(r6)
            com.quizlet.quizletandroid.managers.audio.h r6 = r4.e     // Catch: java.io.IOException -> L27 java.lang.IllegalStateException -> L29
            if (r6 == 0) goto L47
            io.reactivex.rxjava3.internal.operators.completable.a r5 = r6.a(r5)     // Catch: java.io.IOException -> L27 java.lang.IllegalStateException -> L29
            r0.l = r3     // Catch: java.io.IOException -> L27 java.lang.IllegalStateException -> L29
            java.lang.Object r5 = com.google.android.gms.internal.mlkit_vision_camera.I1.a(r5, r0)     // Catch: java.io.IOException -> L27 java.lang.IllegalStateException -> L29
            if (r5 != r1) goto L59
            return r1
        L47:
            java.lang.String r5 = "audioManager"
            kotlin.jvm.internal.Intrinsics.m(r5)     // Catch: java.io.IOException -> L27 java.lang.IllegalStateException -> L29
            r5 = 0
            throw r5     // Catch: java.io.IOException -> L27 java.lang.IllegalStateException -> L29
        L4e:
            timber.log.a r6 = timber.log.c.a
            r6.e(r5)
            goto L59
        L54:
            timber.log.a r6 = timber.log.c.a
            r6.e(r5)
        L59:
            kotlin.Unit r5 = kotlin.Unit.a
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService.b(java.lang.String, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    /* JADX WARN: Code restructure failed: missing block: B:84:0x0107, code lost:
    
        if (r7 == r1) goto L85;
     */
    /* JADX WARN: Removed duplicated region for block: B:39:0x007a  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x007d  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x008c  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object c(com.quizlet.features.flashcards.data.b r7, boolean r8, kotlin.coroutines.jvm.internal.c r9) {
        /*
            Method dump skipped, instructions count: 272
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService.c(com.quizlet.features.flashcards.data.b, boolean, kotlin.coroutines.jvm.internal.c):java.lang.Object");
    }

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.a == null) {
            synchronized (this.b) {
                try {
                    if (this.a == null) {
                        this.a = new dagger.hilt.android.internal.managers.i(this);
                    }
                } finally {
                }
            }
        }
        return this.a.d();
    }

    public final void e() {
        if (!this.c) {
            this.c = true;
            com.quizlet.quizletandroid.o oVar = (com.quizlet.quizletandroid.o) ((n) d());
            oVar.getClass();
            this.d = new a();
            u uVar = oVar.a;
            this.e = (com.quizlet.quizletandroid.managers.audio.h) uVar.a2.get();
            Context applicationContext = uVar.q();
            Intrinsics.checkNotNullParameter(applicationContext, "applicationContext");
            C1034v c1034v = new C1034v(applicationContext, "no_sound_flashcard_auto_play_notification_channel");
            c1034v.e = C1034v.b("Flashcards Autoplay");
            c1034v.f = C1034v.b("");
            Intrinsics.checkNotNullExpressionValue(c1034v, "setContentText(...)");
            this.f = c1034v;
            Context context = uVar.q();
            Intrinsics.checkNotNullParameter(context, "context");
            Object systemService = context.getSystemService("notification");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.NotificationManager");
            this.g = (NotificationManager) systemService;
            kotlinx.coroutines.scheduling.e eVar = O.a;
            this.h = E.c(kotlinx.coroutines.scheduling.d.b);
        }
        super.onCreate();
    }

    /* JADX WARN: Code restructure failed: missing block: B:40:0x00b1, code lost:
    
        if (kotlinx.coroutines.E.n(r13, r0) != r1) goto L42;
     */
    /* JADX WARN: Removed duplicated region for block: B:35:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:7:0x0013  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.Object f(java.lang.String r13, kotlin.coroutines.jvm.internal.c r14, boolean r15) {
        /*
            r12 = this;
            boolean r0 = r14 instanceof com.quizlet.features.flashcards.autoplay.m
            if (r0 == 0) goto L13
            r0 = r14
            com.quizlet.features.flashcards.autoplay.m r0 = (com.quizlet.features.flashcards.autoplay.m) r0
            int r1 = r0.o
            r2 = -2147483648(0xffffffff80000000, float:-0.0)
            r3 = r1 & r2
            if (r3 == 0) goto L13
            int r1 = r1 - r2
            r0.o = r1
            goto L18
        L13:
            com.quizlet.features.flashcards.autoplay.m r0 = new com.quizlet.features.flashcards.autoplay.m
            r0.<init>(r12, r14)
        L18:
            java.lang.Object r14 = r0.m
            kotlin.coroutines.intrinsics.a r1 = kotlin.coroutines.intrinsics.a.a
            int r2 = r0.o
            r3 = 1
            r5 = 4
            r6 = 3
            r7 = 2
            r8 = 1
            r9 = 0
            if (r2 == 0) goto L50
            if (r2 == r8) goto L46
            if (r2 == r7) goto L40
            if (r2 == r6) goto L3c
            if (r2 != r5) goto L34
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto Lb4
        L34:
            java.lang.IllegalStateException r13 = new java.lang.IllegalStateException
            java.lang.String r14 = "call to 'resume' before 'invoke' with coroutine"
            r13.<init>(r14)
            throw r13
        L3c:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto La3
        L40:
            com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService r13 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L84
        L46:
            boolean r15 = r0.l
            java.lang.String r13 = r0.k
            com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService r2 = r0.j
            androidx.glance.appwidget.protobuf.Z.e(r14)
            goto L69
        L50:
            androidx.glance.appwidget.protobuf.Z.e(r14)
            java.util.concurrent.TimeUnit r14 = java.util.concurrent.TimeUnit.SECONDS
            long r10 = r14.toMillis(r3)
            r0.j = r12
            r0.k = r13
            r0.l = r15
            r0.o = r8
            java.lang.Object r14 = kotlinx.coroutines.E.n(r10, r0)
            if (r14 != r1) goto L68
            goto Lb3
        L68:
            r2 = r12
        L69:
            if (r15 == 0) goto L8e
            if (r13 == 0) goto L8e
            androidx.lifecycle.X r14 = r2.i
            if (r14 == 0) goto L76
            com.quizlet.features.flashcards.autoplay.d r15 = com.quizlet.features.flashcards.autoplay.d.a
            r14.j(r15)
        L76:
            r0.j = r2
            r0.k = r9
            r0.o = r7
            java.lang.Object r13 = r2.b(r13, r0)
            if (r13 != r1) goto L83
            goto Lb3
        L83:
            r13 = r2
        L84:
            androidx.lifecycle.X r13 = r13.i
            if (r13 == 0) goto La3
            com.quizlet.features.flashcards.autoplay.d r14 = com.quizlet.features.flashcards.autoplay.d.c
            r13.j(r14)
            goto La3
        L8e:
            java.util.concurrent.TimeUnit r13 = java.util.concurrent.TimeUnit.SECONDS
            r14 = 2
            long r13 = r13.toMillis(r14)
            r0.j = r9
            r0.k = r9
            r0.o = r6
            java.lang.Object r13 = kotlinx.coroutines.E.n(r13, r0)
            if (r13 != r1) goto La3
            goto Lb3
        La3:
            java.util.concurrent.TimeUnit r13 = java.util.concurrent.TimeUnit.SECONDS
            long r13 = r13.toMillis(r3)
            r0.j = r9
            r0.o = r5
            java.lang.Object r13 = kotlinx.coroutines.E.n(r13, r0)
            if (r13 != r1) goto Lb4
        Lb3:
            return r1
        Lb4:
            kotlin.Unit r13 = kotlin.Unit.a
            return r13
        */
        throw new UnsupportedOperationException("Method not decompiled: com.quizlet.features.flashcards.autoplay.FlashcardsAutoplayService.f(java.lang.String, kotlin.coroutines.jvm.internal.c, boolean):java.lang.Object");
    }

    public final void g() {
        timber.log.c.a.g("Service is shut down", new Object[0]);
        this.k = false;
        com.quizlet.features.flashcards.engine.h hVar = this.j;
        if (hVar != null) {
            hVar.q(com.quizlet.features.infra.models.flashcards.d.a(hVar.d(), null, null, false, false, 0L, 0, 495));
        }
        com.quizlet.quizletandroid.managers.audio.h hVar2 = this.e;
        if (hVar2 == null) {
            Intrinsics.m("audioManager");
            throw null;
        }
        hVar2.b(true);
        kotlinx.coroutines.internal.d dVar = this.h;
        if (dVar == null) {
            Intrinsics.m("mainScope");
            throw null;
        }
        E.i(dVar, null);
        stopSelf();
    }

    public final void h(q startingState) {
        Intrinsics.checkNotNullParameter(startingState, "startingState");
        y0 y0Var = this.n;
        if (y0Var != null) {
            y0Var.j(null);
        }
        this.j = startingState.c;
        this.m = startingState.b;
        kotlinx.coroutines.internal.d dVar = this.h;
        if (dVar != null) {
            this.n = E.A(dVar, com.facebook.appevents.iap.u.d(), null, new l(startingState.a, this, null), 2);
        } else {
            Intrinsics.m("mainScope");
            throw null;
        }
    }

    @Override // android.app.Service
    public final IBinder onBind(Intent intent) {
        timber.log.c.a.g("Service is bound", new Object[0]);
        a aVar = this.d;
        if (aVar == null) {
            Intrinsics.m("binder");
            throw null;
        }
        aVar.a = this;
        if (aVar != null) {
            return aVar;
        }
        Intrinsics.m("binder");
        throw null;
    }

    @Override // android.app.Service
    public final void onCreate() {
        e();
        NotificationManager notificationManager = this.g;
        if (notificationManager == null) {
            Intrinsics.m("notificationManager");
            throw null;
        }
        notificationManager.createNotificationChannel(new NotificationChannel("flashcards_autoplay_notification_channel", "Flashcards_Autoplay", 2));
        try {
            int i = Build.VERSION.SDK_INT;
            if (i < 29) {
                C1034v c1034v = this.f;
                if (c1034v != null) {
                    startForeground(1, c1034v.a());
                    return;
                } else {
                    Intrinsics.m("notificationBuilder");
                    throw null;
                }
            }
            C1034v c1034v2 = this.f;
            if (c1034v2 == null) {
                Intrinsics.m("notificationBuilder");
                throw null;
            }
            Notification notificationA = c1034v2.a();
            if (i >= 34) {
                AbstractC1020g.g(this, notificationA);
            } else if (i >= 29) {
                AbstractC1020g.f(this, notificationA);
            } else {
                startForeground(1, notificationA);
            }
        } catch (ForegroundServiceStartNotAllowedException e) {
            if (Build.VERSION.SDK_INT < 31) {
                throw e;
            }
            stopSelf();
        }
    }

    @Override // android.app.Service
    public final void onDestroy() {
        timber.log.c.a.g("Service is destroyed", new Object[0]);
        g();
        super.onDestroy();
    }

    @Override // android.app.Service
    public final int onStartCommand(Intent intent, int i, int i2) {
        timber.log.c.a.g("Service is started", new Object[0]);
        this.k = true;
        return super.onStartCommand(intent, i, i2);
    }

    @Override // android.app.Service
    public final void onTaskRemoved(Intent intent) {
        g();
    }

    @Override // android.app.Service
    public final boolean onUnbind(Intent intent) {
        timber.log.c.a.g("Service unbound", new Object[0]);
        a aVar = this.d;
        if (aVar != null) {
            aVar.a = null;
            return super.onUnbind(intent);
        }
        Intrinsics.m("binder");
        throw null;
    }
}
