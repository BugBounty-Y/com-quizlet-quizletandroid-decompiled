package com.perimeterx.mobile_sdk.detections.device.touch_interception;

/* loaded from: classes2.dex */
public final class a {
    public final int a;
    public final int b;
    public final int c;

    public a(int i, int i2, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.a);
        sb.append(',');
        sb.append(this.b);
        sb.append(',');
        sb.append(this.c / 1000);
        return sb.toString();
    }
}
