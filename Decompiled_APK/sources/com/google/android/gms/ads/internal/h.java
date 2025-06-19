package com.google.android.gms.ads.internal;

import android.net.Uri;
import android.os.AsyncTask;
import android.webkit.WebView;
import androidx.camera.camera2.internal.c0;
import com.amazon.device.ads.DtbConstants;
import com.google.android.gms.internal.ads.L7;
import com.google.android.gms.internal.ads.P4;
import com.google.android.gms.internal.ads.zzavm;
import java.util.TreeMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/* loaded from: classes2.dex */
public final class h extends AsyncTask {
    public final /* synthetic */ i a;

    public /* synthetic */ h(i iVar) {
        this.a = iVar;
    }

    @Override // android.os.AsyncTask
    public final Object doInBackground(Object[] objArr) {
        i iVar = this.a;
        try {
            iVar.h = (P4) iVar.c.get(1000L, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            e = e;
            com.google.android.gms.ads.internal.util.client.i.i("", e);
        } catch (ExecutionException e2) {
            e = e2;
            com.google.android.gms.ads.internal.util.client.i.i("", e);
        } catch (TimeoutException e3) {
            com.google.android.gms.ads.internal.util.client.i.i("", e3);
        }
        iVar.getClass();
        Uri.Builder builder = new Uri.Builder();
        builder.scheme(DtbConstants.HTTPS).appendEncodedPath((String) L7.d.o());
        c0 c0Var = iVar.e;
        builder.appendQueryParameter("query", (String) c0Var.e);
        builder.appendQueryParameter("pubId", (String) c0Var.c);
        builder.appendQueryParameter("mappver", (String) c0Var.g);
        TreeMap treeMap = (TreeMap) c0Var.d;
        for (String str : treeMap.keySet()) {
            builder.appendQueryParameter(str, (String) treeMap.get(str));
        }
        Uri uriBuild = builder.build();
        P4 p4 = iVar.h;
        if (p4 != null) {
            try {
                uriBuild = P4.d(uriBuild, p4.b.b(iVar.d));
            } catch (zzavm e4) {
                com.google.android.gms.ads.internal.util.client.i.i("Unable to process ad data", e4);
            }
        }
        return android.support.v4.media.session.a.l(iVar.p(), "#", uriBuild.getEncodedQuery());
    }

    @Override // android.os.AsyncTask
    public final /* bridge */ /* synthetic */ void onPostExecute(Object obj) {
        String str = (String) obj;
        WebView webView = this.a.f;
        if (webView == null || str == null) {
            return;
        }
        webView.loadUrl(str);
    }
}
