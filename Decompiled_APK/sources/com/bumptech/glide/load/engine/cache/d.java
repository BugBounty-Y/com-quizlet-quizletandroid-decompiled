package com.bumptech.glide.load.engine.cache;

import androidx.camera.camera2.internal.C0148z;
import com.bumptech.glide.load.engine.l;
import com.bumptech.glide.load.engine.v;

/* loaded from: classes.dex */
public final class d extends C0148z {
    public l e;

    @Override // androidx.camera.camera2.internal.C0148z
    public final int d(Object obj) {
        v vVar = (v) obj;
        if (vVar == null) {
            return 1;
        }
        return vVar.a();
    }

    @Override // androidx.camera.camera2.internal.C0148z
    public final void e(Object obj, Object obj2) {
        v vVar = (v) obj2;
        l lVar = this.e;
        if (lVar == null || vVar == null) {
            return;
        }
        lVar.e.F(vVar, true);
    }
}
