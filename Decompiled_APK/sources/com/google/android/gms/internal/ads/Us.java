package com.google.android.gms.internal.ads;

import com.google.android.gms.tasks.Task;

/* loaded from: classes2.dex */
public final class Us extends AbstractC2460ov {
    public Task h;

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final String e() {
        Task task = this.h;
        return task == null ? "" : task.toString();
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2460ov
    public final void f() {
        this.h = null;
    }
}
