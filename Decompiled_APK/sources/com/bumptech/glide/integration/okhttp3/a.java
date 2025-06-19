package com.bumptech.glide.integration.okhttp3;

import android.util.Log;
import com.bumptech.glide.load.HttpException;
import com.bumptech.glide.load.data.e;
import com.bumptech.glide.load.model.h;
import com.bumptech.glide.util.d;
import com.bumptech.glide.util.f;
import com.google.firebase.perf.network.FirebasePerfOkHttpClient;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import okhttp3.A;
import okhttp3.C;
import okhttp3.H;
import okhttp3.InterfaceC5075d;
import okhttp3.InterfaceC5076e;
import okhttp3.InterfaceC5077f;
import okhttp3.J;
import okhttp3.internal.connection.g;

/* loaded from: classes.dex */
public final class a implements e, InterfaceC5077f {
    public final InterfaceC5075d a;
    public final h b;
    public d c;
    public J d;
    public com.bumptech.glide.load.data.d e;
    public volatile g f;

    public a(InterfaceC5075d interfaceC5075d, h hVar) {
        this.a = interfaceC5075d;
        this.b = hVar;
    }

    @Override // com.bumptech.glide.load.data.e
    public final void cancel() {
        g gVar = this.f;
        if (gVar != null) {
            gVar.cancel();
        }
    }

    @Override // com.bumptech.glide.load.data.e
    public final void f() throws IOException {
        try {
            d dVar = this.c;
            if (dVar != null) {
                dVar.close();
            }
        } catch (IOException unused) {
        }
        J j = this.d;
        if (j != null) {
            j.close();
        }
        this.e = null;
    }

    @Override // com.bumptech.glide.load.data.e
    public final int g() {
        return 2;
    }

    @Override // com.bumptech.glide.load.data.e
    public final Class getDataClass() {
        return InputStream.class;
    }

    @Override // com.bumptech.glide.load.data.e
    public final void h(com.bumptech.glide.g gVar, com.bumptech.glide.load.data.d dVar) {
        com.quizlet.remote.model.notes.e eVar = new com.quizlet.remote.model.notes.e(13);
        eVar.r(this.b.d());
        for (Map.Entry entry : this.b.b.b().entrySet()) {
            eVar.h((String) entry.getKey(), (String) entry.getValue());
        }
        C cI = eVar.i();
        this.e = dVar;
        this.f = ((A) this.a).c(cI);
        FirebasePerfOkHttpClient.enqueue(this.f, this);
    }

    @Override // okhttp3.InterfaceC5077f
    public final void onFailure(InterfaceC5076e interfaceC5076e, IOException iOException) {
        Log.isLoggable("OkHttpFetcher", 3);
        this.e.a(iOException);
    }

    @Override // okhttp3.InterfaceC5077f
    public final void onResponse(InterfaceC5076e interfaceC5076e, H h) {
        this.d = h.g;
        if (!h.d()) {
            this.e.a(new HttpException(h.c, h.d, null));
            return;
        }
        J j = this.d;
        f.c(j, "Argument must not be null");
        d dVar = new d(this.d.f0().i0(), j.a());
        this.c = dVar;
        this.e.i(dVar);
    }
}
