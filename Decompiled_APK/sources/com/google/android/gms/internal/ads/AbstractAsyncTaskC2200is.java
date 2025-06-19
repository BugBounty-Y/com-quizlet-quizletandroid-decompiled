package com.google.android.gms.internal.ads;

import android.os.AsyncTask;
import java.util.ArrayDeque;
import java.util.concurrent.ThreadPoolExecutor;

/* renamed from: com.google.android.gms.internal.ads.is, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractAsyncTaskC2200is extends AsyncTask {
    public C2326lq a;
    public final Fi b;

    public AbstractAsyncTaskC2200is(Fi fi) {
        this.b = fi;
    }

    @Override // android.os.AsyncTask
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public void onPostExecute(String str) {
        C2326lq c2326lq = this.a;
        if (c2326lq != null) {
            c2326lq.d = null;
            AbstractAsyncTaskC2200is abstractAsyncTaskC2200is = (AbstractAsyncTaskC2200is) ((ArrayDeque) c2326lq.c).poll();
            c2326lq.d = abstractAsyncTaskC2200is;
            if (abstractAsyncTaskC2200is != null) {
                abstractAsyncTaskC2200is.executeOnExecutor((ThreadPoolExecutor) c2326lq.b, new Object[0]);
            }
        }
    }
}
