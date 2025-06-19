package com.google.android.gms.internal.ads;

import android.net.Uri;
import android.text.TextUtils;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/* renamed from: com.google.android.gms.internal.ads.je, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2228je extends AbstractC2802wu implements InterfaceC2648tB {
    public static final Pattern v = Pattern.compile("^bytes (\\d+)-(\\d+)/(\\d+)$");
    public final int e;
    public final int f;
    public final String g;
    public final Fp h;
    public C2891yx i;
    public HttpURLConnection j;
    public final ArrayDeque k;
    public InputStream l;
    public boolean m;
    public int n;
    public long o;
    public long p;
    public long q;
    public long r;
    public long s;
    public final long t;
    public final long u;

    public C2228je(String str, C2143he c2143he, int i, int i2, long j, long j2) {
        super(true);
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException();
        }
        this.g = str;
        this.h = new Fp(7);
        this.e = i;
        this.f = i2;
        this.k = new ArrayDeque();
        this.t = j;
        this.u = j2;
        if (c2143he != null) {
            m(c2143he);
        }
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final Uri a() {
        HttpURLConnection httpURLConnection = this.j;
        if (httpURLConnection == null) {
            return null;
        }
        return Uri.parse(httpURLConnection.getURL().toString());
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final long c(C2891yx c2891yx) throws IOException, NumberFormatException {
        this.i = c2891yx;
        this.p = 0L;
        long j = c2891yx.c;
        long j2 = c2891yx.d;
        long jMin = this.t;
        if (j2 != -1) {
            jMin = Math.min(jMin, j2);
        }
        this.q = j;
        HttpURLConnection httpURLConnectionQ = q(j, (jMin + j) - 1, 1);
        this.j = httpURLConnectionQ;
        String headerField = httpURLConnectionQ.getHeaderField("Content-Range");
        if (!TextUtils.isEmpty(headerField)) {
            Matcher matcher = v.matcher(headerField);
            if (matcher.find()) {
                try {
                    Long.parseLong(matcher.group(1));
                    long j3 = Long.parseLong(matcher.group(2));
                    long j4 = Long.parseLong(matcher.group(3));
                    if (j2 != -1) {
                        this.o = j2;
                        this.r = Math.max(j3, (this.q + j2) - 1);
                    } else {
                        this.o = j4 - this.q;
                        this.r = j4 - 1;
                    }
                    this.s = j3;
                    this.m = true;
                    p(c2891yx);
                    return this.o;
                } catch (NumberFormatException unused) {
                    com.google.android.gms.ads.internal.util.client.i.e("Unexpected Content-Range [" + headerField + "]");
                }
            }
        }
        throw new C2187ie("Invalid content range: ".concat(String.valueOf(headerField)), 2000, 1);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2779wD
    public final int d(int i, byte[] bArr, int i2) throws IOException {
        if (i2 == 0) {
            return 0;
        }
        try {
            long j = this.o;
            long j2 = this.p;
            if (j - j2 == 0) {
                return -1;
            }
            long j3 = this.q + j2;
            long j4 = i2;
            long j5 = j3 + j4 + this.u;
            long j6 = this.s;
            long j7 = j6 + 1;
            if (j5 > j7) {
                long j8 = this.r;
                if (j6 < j8) {
                    long jMin = Math.min(j8, Math.max(((this.t + j7) - r4) - 1, (j7 + j4) - 1));
                    q(j7, jMin, 2);
                    this.s = jMin;
                    j6 = jMin;
                }
            }
            int i3 = this.l.read(bArr, i, (int) Math.min(j4, ((j6 + 1) - this.q) - this.p));
            if (i3 == -1) {
                throw new EOFException();
            }
            this.p += i3;
            e(i3);
            return i3;
        } catch (IOException e) {
            throw new zzgx(e, 2000, 2);
        }
    }

    @Override // com.google.android.gms.internal.ads.Fw
    public final void j() {
        try {
            InputStream inputStream = this.l;
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    throw new zzgx(e, 2000, 3);
                }
            }
        } finally {
            this.l = null;
            r();
            if (this.m) {
                this.m = false;
                b();
            }
        }
    }

    public final HttpURLConnection q(long j, long j2, int i) throws IOException {
        String string = this.i.a.toString();
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(string).openConnection();
            httpURLConnection.setConnectTimeout(this.e);
            httpURLConnection.setReadTimeout(this.f);
            for (Map.Entry entry : this.h.d().entrySet()) {
                httpURLConnection.setRequestProperty((String) entry.getKey(), (String) entry.getValue());
            }
            httpURLConnection.setRequestProperty("Range", "bytes=" + j + "-" + j2);
            httpURLConnection.setRequestProperty("User-Agent", this.g);
            httpURLConnection.setRequestProperty("Accept-Encoding", "identity");
            httpURLConnection.setRequestMethod("GET");
            httpURLConnection.connect();
            this.k.add(httpURLConnection);
            String string2 = this.i.a.toString();
            try {
                int responseCode = httpURLConnection.getResponseCode();
                this.n = responseCode;
                if (responseCode < 200 || responseCode > 299) {
                    httpURLConnection.getHeaderFields();
                    r();
                    throw new C2187ie(android.support.v4.media.session.a.f(this.n, "Response code: "), 2000, i);
                }
                try {
                    InputStream inputStream = httpURLConnection.getInputStream();
                    if (this.l != null) {
                        inputStream = new SequenceInputStream(this.l, inputStream);
                    }
                    this.l = inputStream;
                    return httpURLConnection;
                } catch (IOException e) {
                    r();
                    throw new zzgx(e, 2000, i);
                }
            } catch (IOException e2) {
                r();
                throw new zzgx("Unable to connect to ".concat(String.valueOf(string2)), e2, 2000, i);
            }
        } catch (IOException e3) {
            throw new zzgx("Unable to connect to ".concat(String.valueOf(string)), e3, 2000, i);
        }
    }

    public final void r() {
        while (true) {
            ArrayDeque arrayDeque = this.k;
            if (arrayDeque.isEmpty()) {
                this.j = null;
                return;
            } else {
                try {
                    ((HttpURLConnection) arrayDeque.remove()).disconnect();
                } catch (Exception e) {
                    com.google.android.gms.ads.internal.util.client.i.f("Unexpected error while disconnecting", e);
                }
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.AbstractC2802wu, com.google.android.gms.internal.ads.Fw
    public final Map zze() {
        HttpURLConnection httpURLConnection = this.j;
        if (httpURLConnection == null) {
            return null;
        }
        return httpURLConnection.getHeaderFields();
    }
}
