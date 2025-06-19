package com.facebook.internal;

import android.content.BroadcastReceiver;
import android.content.Context;
import kotlin.jvm.internal.Intrinsics;

/* renamed from: com.facebook.internal.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1549d extends BroadcastReceiver {
    public static C1549d c;
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ C1549d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    public static final /* synthetic */ C1549d a() {
        if (com.facebook.internal.instrument.crashshield.a.b(C1549d.class)) {
            return null;
        }
        try {
            return c;
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(C1549d.class, th);
            return null;
        }
    }

    public void finalize() throws Throwable {
        switch (this.a) {
            case 0:
                if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                    try {
                        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                            try {
                                androidx.localbroadcastmanager.content.b bVarA = androidx.localbroadcastmanager.content.b.a((Context) this.b);
                                Intrinsics.checkNotNullExpressionValue(bVarA, "getInstance(applicationContext)");
                                bVarA.d(this);
                                break;
                            } catch (Throwable th) {
                                com.facebook.internal.instrument.crashshield.a.a(this, th);
                                return;
                            }
                        }
                    } catch (Throwable th2) {
                        com.facebook.internal.instrument.crashshield.a.a(this, th2);
                        return;
                    }
                }
                break;
            default:
                super.finalize();
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:21:0x0052  */
    @Override // android.content.BroadcastReceiver
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void onReceive(android.content.Context r9, android.content.Intent r10) {
        /*
            Method dump skipped, instructions count: 928
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.internal.C1549d.onReceive(android.content.Context, android.content.Intent):void");
    }

    public /* synthetic */ C1549d(boolean z, int i, Object obj) {
        this.a = i;
        this.b = obj;
    }

    public C1549d(Context context) {
        this.a = 0;
        Context applicationContext = context.getApplicationContext();
        Intrinsics.checkNotNullExpressionValue(applicationContext, "context.applicationContext");
        this.b = applicationContext;
    }
}
