package com.google.android.gms.internal.ads;

import android.graphics.SurfaceTexture;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;

/* renamed from: com.google.android.gms.internal.ads.m, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class HandlerThreadC2336m extends HandlerThread implements Handler.Callback {
    public Ij a;
    public Handler b;
    public Error c;
    public RuntimeException d;
    public zzaax e;

    @Override // android.os.Handler.Callback
    public final boolean handleMessage(Message message) {
        Ij ij;
        int i = message.what;
        try {
            if (i == 1) {
                try {
                    int i2 = message.arg1;
                    Ij ij2 = this.a;
                    if (ij2 == null) {
                        throw null;
                    }
                    ij2.a(i2);
                    SurfaceTexture surfaceTexture = this.a.f;
                    surfaceTexture.getClass();
                    this.e = new zzaax(this, surfaceTexture, i2 != 0);
                    synchronized (this) {
                        notify();
                    }
                    return true;
                } catch (zzdn e) {
                    AbstractC2096gb.A("PlaceholderSurface", "Failed to initialize placeholder surface", e);
                    this.d = new IllegalStateException(e);
                    synchronized (this) {
                        notify();
                    }
                } catch (Error e2) {
                    AbstractC2096gb.A("PlaceholderSurface", "Failed to initialize placeholder surface", e2);
                    this.c = e2;
                    synchronized (this) {
                        notify();
                    }
                } catch (RuntimeException e3) {
                    AbstractC2096gb.A("PlaceholderSurface", "Failed to initialize placeholder surface", e3);
                    this.d = e3;
                    synchronized (this) {
                        notify();
                    }
                }
            } else if (i == 2) {
                try {
                    ij = this.a;
                } finally {
                    try {
                        return true;
                    } finally {
                    }
                }
                if (ij == null) {
                    throw null;
                }
                ij.b();
                return true;
            }
            return true;
        } catch (Throwable th) {
            synchronized (this) {
                notify();
                throw th;
            }
        }
    }
}
