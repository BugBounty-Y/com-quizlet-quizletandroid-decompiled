package com.perimeterx.mobile_sdk.local_data;

import com.google.android.gms.internal.mlkit_vision_camera.AbstractC3328d;

/* JADX WARN: Failed to restore enum class, 'enum' modifier and super class removed */
/* JADX WARN: Unknown enum class pattern. Please report as an issue! */
/* loaded from: classes2.dex */
public final class y {
    public static final y a;
    public static final y b;
    public static final y c;
    public static final /* synthetic */ y[] d;

    static {
        y yVar = new y("STRING", 0);
        a = yVar;
        y yVar2 = new y("INT", 1);
        b = yVar2;
        y yVar3 = new y("BOOLEAN", 2);
        c = yVar3;
        y[] yVarArr = {yVar, yVar2, yVar3};
        d = yVarArr;
        AbstractC3328d.f(yVarArr);
    }

    public static y valueOf(String str) {
        return (y) Enum.valueOf(y.class, str);
    }

    public static y[] values() {
        return (y[]) d.clone();
    }
}
