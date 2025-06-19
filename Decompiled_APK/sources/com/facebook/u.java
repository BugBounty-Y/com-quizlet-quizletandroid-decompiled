package com.facebook;

import android.os.AsyncTask;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import java.util.Arrays;
import java.util.List;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class u extends AsyncTask {
    public final v a;
    public Exception b;

    public u(v requests) {
        Intrinsics.checkNotNullParameter(requests, "requests");
        Intrinsics.checkNotNullParameter(requests, "requests");
        this.a = requests;
    }

    @Override // android.os.AsyncTask
    public final Object doInBackground(Object[] objArr) {
        if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
            try {
                Void[] params = (Void[]) objArr;
                if (!com.facebook.internal.instrument.crashshield.a.b(this)) {
                    try {
                        Intrinsics.checkNotNullParameter(params, "params");
                        try {
                            v vVar = this.a;
                            vVar.getClass();
                            String str = t.j;
                            return assistantMode.utils.studiableMetadata.b.H(vVar);
                        } catch (Exception e) {
                            this.b = e;
                        }
                    } catch (Throwable th) {
                        com.facebook.internal.instrument.crashshield.a.a(this, th);
                    }
                }
            } catch (Throwable th2) {
                com.facebook.internal.instrument.crashshield.a.a(this, th2);
                return null;
            }
        }
        return null;
    }

    @Override // android.os.AsyncTask
    public final void onPostExecute(Object obj) {
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            List result = (List) obj;
            if (com.facebook.internal.instrument.crashshield.a.b(this)) {
                return;
            }
            try {
                Intrinsics.checkNotNullParameter(result, "result");
                super.onPostExecute(result);
                Exception exc = this.b;
                if (exc != null) {
                    Intrinsics.checkNotNullExpressionValue(String.format("onPostExecute: exception encountered during request: %s", Arrays.copyOf(new Object[]{exc.getMessage()}, 1)), "format(format, *args)");
                    o oVar = o.a;
                }
            } catch (Throwable th) {
                com.facebook.internal.instrument.crashshield.a.a(this, th);
            }
        } catch (Throwable th2) {
            com.facebook.internal.instrument.crashshield.a.a(this, th2);
        }
    }

    @Override // android.os.AsyncTask
    public final void onPreExecute() {
        v vVar = this.a;
        if (com.facebook.internal.instrument.crashshield.a.b(this)) {
            return;
        }
        try {
            super.onPreExecute();
            o oVar = o.a;
            if (vVar.a == null) {
                vVar.a = Thread.currentThread() instanceof HandlerThread ? new Handler() : new Handler(Looper.getMainLooper());
            }
        } catch (Throwable th) {
            com.facebook.internal.instrument.crashshield.a.a(this, th);
        }
    }

    public final String toString() {
        String str = "{RequestAsyncTask:  connection: null, requests: " + this.a + "}";
        Intrinsics.checkNotNullExpressionValue(str, "StringBuilder()\n        …(\"}\")\n        .toString()");
        return str;
    }
}
