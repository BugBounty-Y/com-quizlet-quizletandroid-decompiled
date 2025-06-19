package com.perimeterx.mobile_sdk.detections.device.motion_interception;

/* loaded from: classes2.dex */
public final class a {
    public final int a;
    public final int b;
    public final int c;
    public final int d;

    public a(int i, int i2, int i3, int i4) {
        this.a = i;
        this.b = i2;
        this.c = i3;
        this.d = i4;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.b);
        sb.append(',');
        sb.append(this.c);
        sb.append(',');
        sb.append(this.d);
        sb.append(',');
        sb.append(this.a / 1000);
        return sb.toString();
    }
}
