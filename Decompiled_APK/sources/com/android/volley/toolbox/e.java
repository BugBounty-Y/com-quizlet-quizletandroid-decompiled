package com.android.volley.toolbox;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;

/* loaded from: classes.dex */
public final class e extends FilterInputStream implements AutoCloseable {
    public final /* synthetic */ int a;
    public final HttpURLConnection b;

    /* JADX WARN: Illegal instructions before constructor call */
    public e(HttpURLConnection httpURLConnection, int i) throws IOException {
        InputStream errorStream;
        InputStream errorStream2;
        this.a = i;
        switch (i) {
            case 1:
                try {
                    errorStream2 = httpURLConnection.getInputStream();
                } catch (IOException unused) {
                    errorStream2 = httpURLConnection.getErrorStream();
                }
                super(errorStream2);
                this.b = httpURLConnection;
                break;
            default:
                try {
                    errorStream = httpURLConnection.getInputStream();
                } catch (IOException unused2) {
                    errorStream = httpURLConnection.getErrorStream();
                }
                super(errorStream);
                this.b = httpURLConnection;
                break;
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        switch (this.a) {
            case 0:
                super.close();
                this.b.disconnect();
                break;
            default:
                super.close();
                this.b.disconnect();
                break;
        }
    }
}
