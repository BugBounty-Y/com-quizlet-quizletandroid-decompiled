package androidx.work.impl.foreground;

import android.app.NotificationManager;
import android.content.Intent;
import android.os.Build;
import android.text.TextUtils;
import androidx.appcompat.app.ExecutorC0060p;
import androidx.lifecycle.M;
import androidx.work.B;
import androidx.work.impl.r;
import androidx.work.z;
import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3402v2;
import com.google.common.util.concurrent.d;
import java.util.UUID;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public class SystemForegroundService extends M {
    public static final String e = z.e("SystemFgService");
    public boolean b;
    public a c;
    public NotificationManager d;

    public final void a() {
        this.d = (NotificationManager) getApplicationContext().getSystemService("notification");
        a aVar = new a(getApplicationContext());
        this.c = aVar;
        if (aVar.i != null) {
            z.c().a(a.j, "A callback already exists.");
        } else {
            aVar.i = this;
        }
    }

    @Override // androidx.lifecycle.M, android.app.Service
    public final void onCreate() {
        super.onCreate();
        a();
    }

    @Override // androidx.lifecycle.M, android.app.Service
    public final void onDestroy() {
        super.onDestroy();
        this.c.e();
    }

    @Override // android.app.Service
    public final int onStartCommand(Intent intent, int i, int i2) {
        super.onStartCommand(intent, i, i2);
        if (this.b) {
            z.c().d(e, "Re-initializing SystemForegroundService after a request to shut-down.");
            this.c.e();
            a();
            this.b = false;
        }
        if (intent == null) {
            return 3;
        }
        a aVar = this.c;
        aVar.getClass();
        String action = intent.getAction();
        boolean zEquals = "ACTION_START_FOREGROUND".equals(action);
        String str = a.j;
        if (zEquals) {
            z.c().d(str, "Started foreground service " + intent);
            aVar.b.a(new d(aVar, false, intent.getStringExtra("KEY_WORKSPEC_ID"), 6));
            aVar.c(intent);
            return 3;
        }
        if ("ACTION_NOTIFY".equals(action)) {
            aVar.c(intent);
            return 3;
        }
        if (!"ACTION_CANCEL_WORK".equals(action)) {
            if (!"ACTION_STOP_FOREGROUND".equals(action)) {
                return 3;
            }
            z.c().d(str, "Stopping foreground service");
            SystemForegroundService systemForegroundService = aVar.i;
            if (systemForegroundService == null) {
                return 3;
            }
            systemForegroundService.b = true;
            z.c().getClass();
            systemForegroundService.stopForeground(true);
            systemForegroundService.stopSelf();
            return 3;
        }
        z.c().d(str, "Stopping foreground work for " + intent);
        String stringExtra = intent.getStringExtra("KEY_WORKSPEC_ID");
        if (stringExtra == null || TextUtils.isEmpty(stringExtra)) {
            return 3;
        }
        UUID id = UUID.fromString(stringExtra);
        r workManagerImpl = aVar.a;
        workManagerImpl.getClass();
        Intrinsics.checkNotNullParameter(id, "id");
        Intrinsics.checkNotNullParameter(workManagerImpl, "workManagerImpl");
        B b = workManagerImpl.b.m;
        ExecutorC0060p executorC0060p = workManagerImpl.d.a;
        Intrinsics.checkNotNullExpressionValue(executorC0060p, "workManagerImpl.workTask…ecutor.serialTaskExecutor");
        AbstractC3402v2.c(b, "CancelWorkById", executorC0060p, new androidx.credentials.playservices.controllers.BeginSignIn.d(13, workManagerImpl, id));
        return 3;
    }

    @Override // android.app.Service
    public final void onTimeout(int i) {
        if (Build.VERSION.SDK_INT >= 35) {
            return;
        }
        this.c.f(2048);
    }

    public final void onTimeout(int i, int i2) {
        this.c.f(i2);
    }
}
