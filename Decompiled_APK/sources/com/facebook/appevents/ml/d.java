package com.facebook.appevents.ml;

import java.io.File;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes.dex */
public final class d {
    public final String a;
    public final String b;
    public final String c;
    public final int d;
    public final float[] e;
    public File f;
    public b g;
    public Runnable h;

    public d(String useCase, String assetUri, String str, int i, float[] fArr) {
        Intrinsics.checkNotNullParameter(useCase, "useCase");
        Intrinsics.checkNotNullParameter(assetUri, "assetUri");
        this.a = useCase;
        this.b = assetUri;
        this.c = str;
        this.d = i;
        this.e = fArr;
    }
}
