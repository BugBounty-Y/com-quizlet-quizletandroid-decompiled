package com.google.firebase.heartbeatinfo;

import android.content.Context;
import com.google.android.gms.internal.mlkit_vision_barcode.AbstractC3233p6;
import com.google.android.gms.internal.mlkit_vision_common.S3;
import com.google.android.gms.tasks.m;
import java.util.Set;
import java.util.concurrent.Executor;

/* loaded from: classes2.dex */
public final class d implements f, g {
    public final com.google.firebase.d a;
    public final Context b;
    public final com.google.firebase.inject.b c;
    public final Set d;
    public final Executor e;

    public d(Context context, String str, Set set, com.google.firebase.inject.b bVar, Executor executor) {
        this.a = new com.google.firebase.d(context, str);
        this.d = set;
        this.e = executor;
        this.c = bVar;
        this.b = context;
    }

    public final m a() {
        if (!AbstractC3233p6.b(this.b)) {
            return S3.i("");
        }
        return S3.g(this.e, new c(this, 0));
    }

    public final void b() {
        if (this.d.size() <= 0) {
            S3.i(null);
        } else if (!AbstractC3233p6.b(this.b)) {
            S3.i(null);
        } else {
            S3.g(this.e, new c(this, 1));
        }
    }
}
