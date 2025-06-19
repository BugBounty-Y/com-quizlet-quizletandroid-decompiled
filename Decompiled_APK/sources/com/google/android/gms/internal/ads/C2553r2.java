package com.google.android.gms.internal.ads;

import com.comscore.android.id.IdHelperAndroid;
import java.util.regex.Pattern;

/* renamed from: com.google.android.gms.internal.ads.r2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2553r2 {
    public static final Pattern d = Pattern.compile("\\s+");
    public static final AbstractC2459ou e = AbstractC2459ou.o(2, "auto", IdHelperAndroid.NO_ID_AVAILABLE);
    public static final AbstractC2459ou f = AbstractC2459ou.o(3, "dot", "sesame", "circle");
    public static final AbstractC2459ou g = AbstractC2459ou.o(2, "filled", "open");
    public static final AbstractC2459ou h = AbstractC2459ou.o(3, "after", "before", "outside");
    public final int a;
    public final int b;
    public final int c;

    public C2553r2(int i, int i2, int i3) {
        this.a = i;
        this.b = i2;
        this.c = i3;
    }
}
