package com.facebook.appevents.iap;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class j implements InvocationHandler {
    public final /* synthetic */ int a;

    public /* synthetic */ j(int i) {
        this.a = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:57:0x0227  */
    /* JADX WARN: Removed duplicated region for block: B:59:0x0233  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public com.facebook.appevents.iap.m a(android.content.Context r45) {
        /*
            Method dump skipped, instructions count: 673
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.iap.j.a(android.content.Context):com.facebook.appevents.iap.m");
    }

    @Override // java.lang.reflect.InvocationHandler
    public final Object invoke(Object proxy, Method m, Object[] objArr) {
        switch (this.a) {
            case 0:
                if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                    try {
                        Intrinsics.checkNotNullParameter(proxy, "proxy");
                        Intrinsics.checkNotNullParameter(m, "m");
                        break;
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(this, th);
                        break;
                    }
                }
                break;
            default:
                Intrinsics.checkNotNullParameter(proxy, "proxy");
                Intrinsics.checkNotNullParameter(m, "m");
                break;
        }
        return null;
        return null;
    }
}
