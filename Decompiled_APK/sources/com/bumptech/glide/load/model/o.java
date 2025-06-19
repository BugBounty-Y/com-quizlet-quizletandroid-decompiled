package com.bumptech.glide.load.model;

import androidx.camera.camera2.internal.C0148z;
import java.util.ArrayDeque;

/* loaded from: classes.dex */
public final class o extends C0148z {
    @Override // androidx.camera.camera2.internal.C0148z
    public final void e(Object obj, Object obj2) {
        p pVar = (p) obj;
        pVar.getClass();
        ArrayDeque arrayDeque = p.b;
        synchronized (arrayDeque) {
            arrayDeque.offer(pVar);
        }
    }
}
