package androidx.camera.core.impl;

import android.util.Range;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/* loaded from: classes.dex */
public final class F {
    public static final C0162c h = new C0162c("camerax.core.captureConfig.rotation", Integer.TYPE, null);
    public static final C0162c i = new C0162c("camerax.core.captureConfig.jpegQuality", Integer.class, null);
    public static final C0162c j = new C0162c("camerax.core.captureConfig.resolvedFrameRate", Range.class, null);
    public final ArrayList a;
    public final C0163c0 b;
    public final int c;
    public final List d;
    public final boolean e;
    public final v0 f;
    public final InterfaceC0177p g;

    public F(ArrayList arrayList, C0163c0 c0163c0, int i2, ArrayList arrayList2, boolean z, v0 v0Var, InterfaceC0177p interfaceC0177p) {
        this.a = arrayList;
        this.b = c0163c0;
        this.c = i2;
        this.d = Collections.unmodifiableList(arrayList2);
        this.e = z;
        this.f = v0Var;
        this.g = interfaceC0177p;
    }

    public final int a() {
        Object objE = 0;
        try {
            objE = this.b.e(A0.w0);
        } catch (IllegalArgumentException unused) {
        }
        Integer num = (Integer) objE;
        Objects.requireNonNull(num);
        return num.intValue();
    }

    public final int b() {
        Object objE = 0;
        try {
            objE = this.b.e(A0.x0);
        } catch (IllegalArgumentException unused) {
        }
        Integer num = (Integer) objE;
        Objects.requireNonNull(num);
        return num.intValue();
    }
}
