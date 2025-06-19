package com.facebook.login;

import android.content.ComponentName;
import java.util.concurrent.locks.ReentrantLock;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.facebook.login.c, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1566c extends androidx.browser.customtabs.m {
    public static androidx.browser.customtabs.l b;
    public static androidx.work.impl.model.n c;
    public static final ReentrantLock d = new ReentrantLock();

    @Override // androidx.browser.customtabs.m
    public final void a(ComponentName name, androidx.browser.customtabs.l newClient) {
        androidx.browser.customtabs.l lVar;
        Intrinsics.checkNotNullParameter(name, "name");
        Intrinsics.checkNotNullParameter(newClient, "newClient");
        newClient.d();
        b = newClient;
        ReentrantLock reentrantLock = d;
        reentrantLock.lock();
        if (c == null && (lVar = b) != null) {
            c = lVar.c(null);
        }
        reentrantLock.unlock();
    }

    @Override // android.content.ServiceConnection
    public final void onServiceDisconnected(ComponentName componentName) {
        Intrinsics.checkNotNullParameter(componentName, "componentName");
    }
}
