package com.google.android.gms.internal.ads;

import java.io.Closeable;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.Set;

/* loaded from: classes2.dex */
public final class Ks implements Closeable {
    public Bt a;
    public Lw b;
    public HttpURLConnection c;

    public final HttpURLConnection a(Lw lw) throws IOException {
        this.a = new Is(1);
        this.b = lw;
        ((Integer) this.a.zza()).getClass();
        Lw lw2 = this.b;
        lw2.getClass();
        Set set = C1800Xd.f;
        L9 l9 = com.google.android.gms.ads.internal.j.C.q;
        int iIntValue = ((Integer) com.google.android.gms.ads.internal.client.r.d.c.a(AbstractC2773w7.G)).intValue();
        URL url = new URL(lw2.b);
        int i = 0;
        while (true) {
            i++;
            if (i > 20) {
                throw new IOException("Too many redirects (20)");
            }
            URLConnection uRLConnectionOpenConnection = url.openConnection();
            uRLConnectionOpenConnection.setConnectTimeout(iIntValue);
            uRLConnectionOpenConnection.setReadTimeout(iIntValue);
            if (!(uRLConnectionOpenConnection instanceof HttpURLConnection)) {
                throw new IOException("Invalid protocol.");
            }
            HttpURLConnection httpURLConnection = (HttpURLConnection) uRLConnectionOpenConnection;
            com.google.android.gms.ads.internal.util.client.f fVar = new com.google.android.gms.ads.internal.util.client.f();
            fVar.a(httpURLConnection, null);
            httpURLConnection.setInstanceFollowRedirects(false);
            int responseCode = httpURLConnection.getResponseCode();
            fVar.b(httpURLConnection, responseCode);
            if (responseCode / 100 != 3) {
                this.c = httpURLConnection;
                return httpURLConnection;
            }
            String headerField = httpURLConnection.getHeaderField("Location");
            if (headerField == null) {
                throw new IOException("Missing Location header in redirect");
            }
            URL url2 = new URL(url, headerField);
            String protocol = url2.getProtocol();
            if (protocol == null) {
                throw new IOException("Protocol is null");
            }
            if (!protocol.equals("http") && !protocol.equals("https")) {
                throw new IOException("Unsupported scheme: ".concat(protocol));
            }
            com.google.android.gms.ads.internal.util.client.i.d("Redirecting to ".concat(headerField));
            httpURLConnection.disconnect();
            url = url2;
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        HttpURLConnection httpURLConnection = this.c;
        if (httpURLConnection != null) {
            httpURLConnection.disconnect();
        }
    }
}
