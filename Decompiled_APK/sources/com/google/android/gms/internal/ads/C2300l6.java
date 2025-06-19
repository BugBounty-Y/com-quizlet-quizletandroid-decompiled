package com.google.android.gms.internal.ads;

import android.os.ParcelFileDescriptor;
import java.io.PushbackInputStream;

/* renamed from: com.google.android.gms.internal.ads.l6, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2300l6 extends PushbackInputStream implements AutoCloseable {
    public final /* synthetic */ C2326lq a;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C2300l6(C2326lq c2326lq, ParcelFileDescriptor.AutoCloseInputStream autoCloseInputStream) {
        super(autoCloseInputStream, 1);
        this.a = c2326lq;
    }

    @Override // java.io.PushbackInputStream, java.io.FilterInputStream, java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public final synchronized void close() {
        com.bumptech.glide.manager.p.i((com.bumptech.glide.manager.p) this.a.d);
        super.close();
    }
}
