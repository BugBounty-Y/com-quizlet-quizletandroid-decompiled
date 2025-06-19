package com.google.android.gms.internal.play_billing;

import sun.misc.Unsafe;

/* renamed from: com.google.android.gms.internal.play_billing.p0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract /* synthetic */ class AbstractC3825p0 {
    public static /* synthetic */ boolean a(Unsafe unsafe, AbstractC3816m0 abstractC3816m0, long j, Object obj, Object obj2) {
        while (!AbstractC3822o0.a(unsafe, abstractC3816m0, j, obj, obj2)) {
            if (unsafe.getObject(abstractC3816m0, j) != obj) {
                return false;
            }
        }
        return true;
    }
}
