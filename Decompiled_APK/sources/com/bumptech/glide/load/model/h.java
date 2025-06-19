package com.bumptech.glide.load.model;

import android.net.Uri;
import android.text.TextUtils;
import java.net.URL;
import java.security.MessageDigest;

/* loaded from: classes.dex */
public final class h implements com.bumptech.glide.load.e {
    public final l b;
    public final URL c;
    public final String d;
    public String e;
    public URL f;
    public volatile byte[] g;
    public int h;

    public h(URL url) {
        l lVar = i.a;
        com.bumptech.glide.util.f.c(url, "Argument must not be null");
        this.c = url;
        this.d = null;
        com.bumptech.glide.util.f.c(lVar, "Argument must not be null");
        this.b = lVar;
    }

    @Override // com.bumptech.glide.load.e
    public final void a(MessageDigest messageDigest) {
        if (this.g == null) {
            this.g = c().getBytes(com.bumptech.glide.load.e.a);
        }
        messageDigest.update(this.g);
    }

    public final String c() {
        String str = this.d;
        if (str != null) {
            return str;
        }
        URL url = this.c;
        com.bumptech.glide.util.f.c(url, "Argument must not be null");
        return url.toString();
    }

    public final String d() {
        if (TextUtils.isEmpty(this.e)) {
            String string = this.d;
            if (TextUtils.isEmpty(string)) {
                URL url = this.c;
                com.bumptech.glide.util.f.c(url, "Argument must not be null");
                string = url.toString();
            }
            this.e = Uri.encode(string, "@#&=*+-_.,:!?()/~'%;$");
        }
        return this.e;
    }

    @Override // com.bumptech.glide.load.e
    public final boolean equals(Object obj) {
        if (!(obj instanceof h)) {
            return false;
        }
        h hVar = (h) obj;
        return c().equals(hVar.c()) && this.b.equals(hVar.b);
    }

    @Override // com.bumptech.glide.load.e
    public final int hashCode() {
        if (this.h == 0) {
            int iHashCode = c().hashCode();
            this.h = iHashCode;
            this.h = this.b.b.hashCode() + (iHashCode * 31);
        }
        return this.h;
    }

    public final String toString() {
        return c();
    }

    public h(String str) {
        l lVar = i.a;
        this.c = null;
        if (!TextUtils.isEmpty(str)) {
            this.d = str;
            com.bumptech.glide.util.f.c(lVar, "Argument must not be null");
            this.b = lVar;
            return;
        }
        throw new IllegalArgumentException("Must not be null or empty");
    }
}
