package com.google.firebase.crashlytics.internal.common;

import android.util.Log;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import java.io.File;
import java.io.IOException;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicReference;
import kotlin.collections.V;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes2.dex */
public final class k implements Callable {
    public final /* synthetic */ long a;
    public final /* synthetic */ Throwable b;
    public final /* synthetic */ Thread c;
    public final /* synthetic */ com.google.android.datatransport.cct.internal.s d;
    public final /* synthetic */ m e;

    public k(m mVar, long j, Throwable th, Thread thread, com.google.android.datatransport.cct.internal.s sVar) {
        this.e = mVar;
        this.a = j;
        this.b = th;
        this.c = thread;
        this.d = sVar;
    }

    @Override // java.util.concurrent.Callable
    public final Object call() throws Throwable {
        com.google.firebase.crashlytics.internal.persistence.c cVar;
        String str;
        long j = this.a;
        long j2 = j / 1000;
        m mVar = this.e;
        String sessionId = mVar.e();
        if (sessionId == null) {
            Log.e("FirebaseCrashlytics", "Tried to write a fatal exception while no session was open.", null);
            return S3.i(null);
        }
        mVar.c.e();
        com.onetrust.otpublishers.headless.UI.TVUI.datautils.d dVar = mVar.m;
        dVar.getClass();
        Log.isLoggable("FirebaseCrashlytics", 2);
        Intrinsics.checkNotNullParameter(sessionId, "sessionId");
        dVar.l(this.b, this.c, "crash", new com.google.firebase.crashlytics.internal.metadata.c(j2, sessionId, V.c()), true);
        try {
            cVar = mVar.g;
            str = ".ae" + j;
            cVar.getClass();
        } catch (IOException e) {
            Log.w("FirebaseCrashlytics", "Could not create app exception marker file.", e);
        }
        if (!new File(cVar.c, str).createNewFile()) {
            throw new IOException("Create new file failed.");
        }
        com.google.android.datatransport.cct.internal.s sVar = this.d;
        mVar.b(false, sVar, false);
        mVar.c(new d().a, Boolean.FALSE);
        return !mVar.b.n() ? S3.i(null) : ((com.google.android.gms.tasks.f) ((AtomicReference) sVar.i).get()).a.n(mVar.e.a, new j(this, sessionId));
    }
}
