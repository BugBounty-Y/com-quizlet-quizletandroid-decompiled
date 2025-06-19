package com.pubmatic.sdk.webrendering.mraid;

/* loaded from: classes2.dex */
public class h {
    final boolean a;
    final String b;
    int c;
    int d;
    int e;
    int f;

    public h(int i, int i2, int i3, int i4, boolean z, String str) {
        this.c = i;
        this.d = i2;
        this.e = i3;
        this.f = i4;
        this.a = z;
        this.b = str;
    }

    public int getHeight() {
        return this.e;
    }

    public String getStatusMsg() {
        return this.b;
    }

    public int getWidth() {
        return this.f;
    }

    public int getxPosition() {
        return this.c;
    }

    public int getyPosition() {
        return this.d;
    }

    public boolean isStatus() {
        return this.a;
    }

    public h(boolean z, String str) {
        this.a = z;
        this.b = str;
    }
}
