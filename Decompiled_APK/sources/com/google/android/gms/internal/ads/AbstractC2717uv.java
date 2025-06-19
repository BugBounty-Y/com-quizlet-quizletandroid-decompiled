package com.google.android.gms.internal.ads;

import sun.misc.Unsafe;

/* renamed from: com.google.android.gms.internal.ads.uv, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract /* synthetic */ class AbstractC2717uv {
    public static /* synthetic */ boolean a(Unsafe unsafe, AbstractC2674tv abstractC2674tv, long j, Object obj, Object obj2) {
        while (!unsafe.compareAndSwapObject(abstractC2674tv, j, obj, obj2)) {
            if (unsafe.getObject(abstractC2674tv, j) != obj) {
                return false;
            }
        }
        return true;
    }
}
