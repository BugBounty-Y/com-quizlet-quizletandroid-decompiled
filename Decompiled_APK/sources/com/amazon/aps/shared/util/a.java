package com.amazon.aps.shared.util;

import android.net.Uri;
import android.util.Log;
import androidx.appcompat.app.K;
import com.google.android.gms.ads.internal.util.client.k;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.concurrent.ExecutorService;

/* loaded from: classes.dex */
public final class a extends Thread {
    public final /* synthetic */ int a;
    public final /* synthetic */ Object b;

    public /* synthetic */ a(Object obj, int i) {
        this.a = i;
        this.b = obj;
    }

    @Override // java.lang.Thread, java.lang.Runnable
    public final void run() {
        Object obj = this.b;
        switch (this.a) {
            case 0:
                try {
                    K k = (K) obj;
                    k.a = true;
                    ((ExecutorService) k.b).shutdown();
                    return;
                } catch (RuntimeException e) {
                    Log.e("K", "Error in stopping the executor", e);
                    return;
                }
            case 1:
                Uri.Builder builderBuildUpon = Uri.parse("https://pagead2.googlesyndication.com/pagead/gen_204?id=gmob-apps").buildUpon();
                HashMap map = (HashMap) obj;
                for (String str : map.keySet()) {
                    builderBuildUpon.appendQueryParameter(str, (String) map.get(str));
                }
                String string = builderBuildUpon.build().toString();
                try {
                    HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(string).openConnection();
                    try {
                        int responseCode = httpURLConnection.getResponseCode();
                        if (responseCode < 200 || responseCode >= 300) {
                            Log.w("HttpUrlPinger", "Received non-success response code " + responseCode + " from pinging URL: " + string);
                        }
                        httpURLConnection.disconnect();
                        return;
                    } catch (Throwable th) {
                        httpURLConnection.disconnect();
                        throw th;
                    }
                } catch (IOException e2) {
                    e = e2;
                    Log.w("HttpUrlPinger", android.support.v4.media.session.a.m("Error while pinging URL: ", string, ". ", e.getMessage()), e);
                    return;
                } catch (IndexOutOfBoundsException e3) {
                    Log.w("HttpUrlPinger", android.support.v4.media.session.a.m("Error while parsing ping URL: ", string, ". ", e3.getMessage()), e3);
                    return;
                } catch (RuntimeException e4) {
                    e = e4;
                    Log.w("HttpUrlPinger", android.support.v4.media.session.a.m("Error while pinging URL: ", string, ". ", e.getMessage()), e);
                    return;
                } finally {
                }
            default:
                new k(null).zza((String) obj);
                return;
        }
    }
}
