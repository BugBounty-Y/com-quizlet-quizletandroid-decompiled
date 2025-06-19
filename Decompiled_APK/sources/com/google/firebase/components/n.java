package com.google.firebase.components;

import android.util.Log;
import androidx.camera.camera2.internal.c0;
import androidx.work.C1446u;
import com.comscore.streaming.EventType;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.Task;
import com.google.firebase.concurrent.ExecutorsRegistrar;
import com.google.firebase.crashlytics.internal.model.O0;
import com.google.firebase.datatransport.TransportRegistrar;
import com.google.firebase.installations.FirebaseInstallationsRegistrar;
import com.google.firebase.perf.FirebasePerfRegistrar;
import com.google.firebase.perf.v1.v;
import com.google.firebase.sessions.FirebaseSessionsRegistrar;
import com.google.protobuf.AbstractC4018l;
import com.google.protobuf.C4016j;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.Charset;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.logging.Logger;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final /* synthetic */ class n implements com.google.firebase.inject.a, d, com.google.android.gms.tasks.c, com.google.android.datatransport.e, com.google.android.gms.tasks.a, com.google.firebase.events.a, com.google.android.gms.tasks.e, io.reactivex.rxjava3.functions.h {
    public final /* synthetic */ int a;

    public /* synthetic */ n(int i) {
        this.a = i;
    }

    public static void a(String message) {
        Intrinsics.checkNotNullParameter(message, "message");
        timber.log.c.a.a(message, new Object[0]);
    }

    @Override // com.google.android.datatransport.e
    public Object apply(Object obj) {
        switch (this.a) {
            case 12:
                com.google.firebase.crashlytics.internal.send.a.b.getClass();
                return com.google.firebase.crashlytics.internal.model.serialization.a.a.n((O0) obj).getBytes(Charset.forName("UTF-8"));
            case 20:
                com.google.firebase.messaging.reporting.e eVar = (com.google.firebase.messaging.reporting.e) obj;
                eVar.getClass();
                com.google.android.gms.internal.appset.e eVar2 = com.google.firebase.messaging.q.a;
                eVar2.getClass();
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                try {
                    eVar2.l(eVar, byteArrayOutputStream);
                } catch (IOException unused) {
                }
                return byteArrayOutputStream.toByteArray();
            case EventType.WINDOW_STATE /* 22 */:
                v vVar = (v) obj;
                vVar.getClass();
                try {
                    int iH = vVar.h(null);
                    byte[] bArr = new byte[iH];
                    Logger logger = AbstractC4018l.d;
                    C4016j c4016j = new C4016j(iH, bArr);
                    vVar.i(c4016j);
                    if (c4016j.H() == 0) {
                        return bArr;
                    }
                    throw new IllegalStateException("Did not write as much data as expected.");
                } catch (IOException e) {
                    throw new RuntimeException(assistantMode.refactored.a.i(v.class, new StringBuilder("Serializing "), " to a byte array threw an IOException (should never happen)."), e);
                }
            default:
                Throwable error = (Throwable) obj;
                Intrinsics.checkNotNullParameter(error, "error");
                return ((error instanceof UnknownHostException) || (error instanceof SocketTimeoutException)) ? new androidx.work.v() : new C1446u();
        }
    }

    @Override // com.google.firebase.components.d
    public Object f(c0 c0Var) {
        switch (this.a) {
            case 1:
                return (ScheduledExecutorService) ExecutorsRegistrar.a.get();
            case 2:
                return (ScheduledExecutorService) ExecutorsRegistrar.c.get();
            case 3:
                return (ScheduledExecutorService) ExecutorsRegistrar.b.get();
            case 4:
                l lVar = ExecutorsRegistrar.a;
                return com.google.firebase.concurrent.j.a;
            case 13:
                return TransportRegistrar.lambda$getComponents$0(c0Var);
            case 14:
                return TransportRegistrar.lambda$getComponents$1(c0Var);
            case 15:
                return TransportRegistrar.lambda$getComponents$2(c0Var);
            case 16:
                return FirebaseInstallationsRegistrar.lambda$getComponents$0(c0Var);
            case 21:
                return FirebasePerfRegistrar.providesFirebasePerformance(c0Var);
            case EventType.AUDIO /* 23 */:
                Set setC = c0Var.c(q.a(com.google.firebase.platforminfo.a.class));
                com.google.firebase.platforminfo.c cVar = com.google.firebase.platforminfo.c.b;
                if (cVar == null) {
                    synchronized (com.google.firebase.platforminfo.c.class) {
                        try {
                            cVar = com.google.firebase.platforminfo.c.b;
                            if (cVar == null) {
                                cVar = new com.google.firebase.platforminfo.c(0);
                                com.google.firebase.platforminfo.c.b = cVar;
                            }
                        } finally {
                        }
                    }
                }
                return new com.google.firebase.platforminfo.b(setC, cVar);
            case EventType.CDN /* 26 */:
                return FirebaseSessionsRegistrar.getComponents$lambda$0(c0Var);
            default:
                return FirebaseSessionsRegistrar.getComponents$lambda$1(c0Var);
        }
    }

    @Override // com.google.android.gms.tasks.e
    public Task g(Object obj) {
        return S3.i(null);
    }

    @Override // com.google.android.gms.tasks.a
    public Object h(Task task) {
        switch (this.a) {
            case 17:
                return 403;
            default:
                return -1;
        }
    }

    @Override // com.google.firebase.inject.a
    public void i(com.google.firebase.inject.b bVar) {
    }

    @Override // com.google.android.gms.tasks.c
    public void t(Exception exc) {
        Log.e("FirebaseCrashlytics", "Error fetching settings.", exc);
    }
}
