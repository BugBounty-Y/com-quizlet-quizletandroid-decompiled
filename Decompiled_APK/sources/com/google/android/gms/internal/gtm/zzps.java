package com.google.android.gms.internal.gtm;

import android.support.v4.media.session.a;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

/* loaded from: classes2.dex */
final class zzps implements zzpt {
    private HttpURLConnection zza;
    private InputStream zzb = null;

    @Override // com.google.android.gms.internal.gtm.zzpt
    public final InputStream zza(String str) throws IOException {
        HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(str).openConnection();
        httpURLConnection.setReadTimeout(20000);
        httpURLConnection.setConnectTimeout(20000);
        this.zza = httpURLConnection;
        int responseCode = httpURLConnection.getResponseCode();
        if (responseCode == 200) {
            InputStream inputStream = httpURLConnection.getInputStream();
            this.zzb = inputStream;
            return inputStream;
        }
        String strF = a.f(responseCode, "Bad response: ");
        if (responseCode == 404) {
            throw new FileNotFoundException(strF);
        }
        if (responseCode == 503) {
            throw new zzpw(strF);
        }
        throw new IOException(strF);
    }

    @Override // com.google.android.gms.internal.gtm.zzpt
    public final void zzb() throws IOException {
        HttpURLConnection httpURLConnection = this.zza;
        try {
            InputStream inputStream = this.zzb;
            if (inputStream != null) {
                inputStream.close();
            }
        } catch (IOException e) {
            zzhi.zzb("HttpUrlConnectionNetworkClient: Error when closing http input stream: ".concat(String.valueOf(e.getMessage())), e);
        }
        if (httpURLConnection != null) {
            httpURLConnection.disconnect();
        }
    }
}
