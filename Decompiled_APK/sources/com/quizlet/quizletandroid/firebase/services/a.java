package com.quizlet.quizletandroid.firebase.services;

import android.app.NotificationManager;
import android.content.Context;
import com.google.firebase.messaging.FirebaseMessagingService;
import com.quizlet.infra.legacysyncengine.managers.d;
import com.quizlet.quizletandroid.o;
import com.quizlet.quizletandroid.u;
import dagger.hilt.android.internal.managers.i;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public abstract class a extends FirebaseMessagingService implements dagger.hilt.internal.b {
    public volatile i a;
    public final Object b = new Object();
    public boolean c = false;

    @Override // dagger.hilt.internal.b
    public final Object d() {
        if (this.a == null) {
            synchronized (this.b) {
                try {
                    if (this.a == null) {
                        this.a = new i(this);
                    }
                } finally {
                }
            }
        }
        return this.a.d();
    }

    @Override // android.app.Service
    public final void onCreate() {
        if (!this.c) {
            this.c = true;
            QuizletFirebaseMessagingService quizletFirebaseMessagingService = (QuizletFirebaseMessagingService) this;
            u uVar = ((o) ((c) d())).a;
            quizletFirebaseMessagingService.d = (d) uVar.Z.get();
            Context contextQ = uVar.q();
            Context context = uVar.q();
            Intrinsics.checkNotNullParameter(context, "context");
            Object systemService = context.getSystemService("notification");
            Intrinsics.e(systemService, "null cannot be cast to non-null type android.app.NotificationManager");
            quizletFirebaseMessagingService.e = new com.quizlet.data.repository.qclass.c((NotificationManager) systemService, contextQ);
        }
        super.onCreate();
    }
}
