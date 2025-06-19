package com.bumptech.glide.load.model;

import android.util.Log;
import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;

/* renamed from: com.bumptech.glide.load.model.d, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1536d implements com.bumptech.glide.load.data.e {
    public final /* synthetic */ int a;
    public final Object b;

    public /* synthetic */ C1536d(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    private final void a() {
    }

    private final void b() {
    }

    private final void c() {
    }

    private final void d() {
    }

    @Override // com.bumptech.glide.load.data.e
    public final void cancel() {
        int i = this.a;
    }

    @Override // com.bumptech.glide.load.data.e
    public final void f() {
        int i = this.a;
    }

    @Override // com.bumptech.glide.load.data.e
    public final int g() {
        switch (this.a) {
        }
        return 1;
    }

    @Override // com.bumptech.glide.load.data.e
    public final Class getDataClass() {
        switch (this.a) {
            case 0:
                return ByteBuffer.class;
            default:
                return this.b.getClass();
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final void h(com.bumptech.glide.g gVar, com.bumptech.glide.load.data.d dVar) {
        switch (this.a) {
            case 0:
                try {
                    dVar.i(com.bumptech.glide.util.b.a((File) this.b));
                    break;
                } catch (IOException e) {
                    Log.isLoggable("ByteBufferFileLoader", 3);
                    dVar.a(e);
                    return;
                }
            default:
                dVar.i(this.b);
                break;
        }
    }
}
