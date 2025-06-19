package com.google.android.gms.ads.internal.util.client;

import com.google.android.gms.ads.internal.client.C1614q;
import com.google.android.gms.ads.internal.client.r;
import com.google.android.gms.internal.ads.AbstractC2773w7;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;

/* loaded from: classes2.dex */
public final class k implements b {
    public final String a;
    public String b;

    public k(String str) {
        this.a = str;
    }

    @Override // com.google.android.gms.ads.internal.util.client.b
    public final j zza(String str) {
        j jVar = j.c;
        j jVar2 = j.b;
        try {
            i.d("Pinging URL: " + str);
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URI(str).toURL().openConnection();
            try {
                c cVar = C1614q.f.a;
                String str2 = this.a;
                httpURLConnection.setConnectTimeout(60000);
                httpURLConnection.setInstanceFollowRedirects(true);
                httpURLConnection.setReadTimeout(60000);
                if (str2 != null) {
                    httpURLConnection.setRequestProperty("User-Agent", str2);
                }
                httpURLConnection.setUseCaches(false);
                f fVar = new f();
                fVar.a(httpURLConnection, null);
                int responseCode = httpURLConnection.getResponseCode();
                fVar.b(httpURLConnection, responseCode);
                if (responseCode < 200 || responseCode >= 300) {
                    i.h("Received non-success response code " + responseCode + " from pinging URL: " + str);
                    if (responseCode == 502) {
                        jVar2 = jVar;
                    }
                } else {
                    if (((Boolean) r.d.c.a(AbstractC2773w7.R7)).booleanValue()) {
                        this.b = httpURLConnection.getHeaderField("X-Afma-Ad-Event-Value");
                    }
                    jVar2 = j.a;
                }
                httpURLConnection.disconnect();
                return jVar2;
            } catch (Throwable th) {
                httpURLConnection.disconnect();
                throw th;
            }
        } catch (IOException e) {
            e = e;
            i.h("Error while pinging URL: " + str + ". " + e.getMessage());
            return jVar;
        } catch (IndexOutOfBoundsException e2) {
            e = e2;
            i.h("Error while parsing ping URL: " + str + ". " + e.getMessage());
            return jVar2;
        } catch (RuntimeException e3) {
            e = e3;
            i.h("Error while pinging URL: " + str + ". " + e.getMessage());
            return jVar;
        } catch (URISyntaxException e4) {
            e = e4;
            i.h("Error while parsing ping URL: " + str + ". " + e.getMessage());
            return jVar2;
        } finally {
        }
    }
}
