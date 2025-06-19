package com.braze.storage;

import com.braze.support.BrazeLogger;
import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.jvm.functions.Function0;

/* renamed from: com.braze.storage.b, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public abstract class AbstractC1515b {
    public final kotlinx.coroutines.sync.e a;

    public AbstractC1515b() {
        int i = kotlinx.coroutines.sync.j.a;
        this.a = new kotlinx.coroutines.sync.i(1, 0);
    }

    public static final String b(AbstractC1515b abstractC1515b) {
        return "Cache locked successfully for export: " + abstractC1515b;
    }

    public final synchronized Object a() {
        int i;
        boolean z;
        Object objC;
        try {
            kotlinx.coroutines.sync.h hVar = (kotlinx.coroutines.sync.h) this.a;
            hVar.getClass();
            while (true) {
                AtomicIntegerFieldUpdater atomicIntegerFieldUpdater = kotlinx.coroutines.sync.h.g;
                int i2 = atomicIntegerFieldUpdater.get(hVar);
                int i3 = hVar.a;
                if (i2 > i3) {
                    do {
                        i = atomicIntegerFieldUpdater.get(hVar);
                        if (i > i3) {
                        }
                    } while (!atomicIntegerFieldUpdater.compareAndSet(hVar, i, i3));
                } else {
                    if (i2 <= 0) {
                        z = false;
                        break;
                    }
                    if (atomicIntegerFieldUpdater.compareAndSet(hVar, i2, i2 - 1)) {
                        z = true;
                        break;
                    }
                }
            }
            if (z) {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new A(this, 1), 7, (Object) null);
                objC = c();
            } else {
                BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, (BrazeLogger.Priority) null, (Throwable) null, false, (Function0) new com.braze.requests.y(25), 7, (Object) null);
                objC = null;
            }
        } catch (Throwable th) {
            throw th;
        }
        return objC;
    }

    public abstract Object c();

    public abstract void c(Object obj, boolean z);

    public static final String b() {
        return "Received call to export dirty object, but the cache was already locked.";
    }

    public static final String b(Object obj, boolean z) {
        return "Tried to confirm outboundObject [" + obj + "] with success [" + z + "], but the cache wasn't locked, so not doing anything.";
    }

    public final synchronized void a(Object obj, boolean z) {
        kotlinx.coroutines.sync.h hVar = (kotlinx.coroutines.sync.h) this.a;
        hVar.getClass();
        if (Math.max(kotlinx.coroutines.sync.h.g.get(hVar), 0) != 0) {
            BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.W, (Throwable) null, false, (Function0) new com.braze.push.g(z, 1, obj), 6, (Object) null);
            return;
        }
        c(obj, z);
        BrazeLogger.brazelog$default(BrazeLogger.INSTANCE, (Object) this, BrazeLogger.Priority.V, (Throwable) null, false, (Function0) new A(this, 0), 6, (Object) null);
        ((kotlinx.coroutines.sync.h) this.a).c();
    }

    public static final String a(AbstractC1515b abstractC1515b) {
        return "Notifying confirmAndUnlock listeners for cache: " + abstractC1515b;
    }
}
