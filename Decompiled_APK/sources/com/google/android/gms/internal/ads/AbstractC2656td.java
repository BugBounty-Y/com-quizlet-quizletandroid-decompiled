package com.google.android.gms.internal.ads;

import android.content.Context;
import android.view.TextureView;

/* renamed from: com.google.android.gms.internal.ads.td, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2656td extends TextureView implements InterfaceC1680Dd {
    public final C2871yd a;
    public final C1686Ed b;

    public AbstractC2656td(Context context) {
        super(context);
        this.a = new C2871yd();
        this.b = new C1686Ed(context, this);
    }

    public Integer A() {
        return null;
    }

    public void B(int i) {
    }

    public void C(int i) {
    }

    public void D(int i) {
    }

    public void b(int i) {
    }

    public void c(int i) {
    }

    public void f(String str, String[] strArr, Integer num) {
        x(str);
    }

    public abstract int j();

    public abstract int k();

    public abstract int l();

    public abstract int n();

    public abstract int o();

    public abstract long p();

    public abstract long q();

    public abstract long r();

    public abstract String s();

    public abstract void t();

    public abstract void u();

    public abstract void v(int i);

    public abstract void w(C2785wd c2785wd);

    public abstract void x(String str);

    public abstract void y();

    public abstract void z(float f, float f2);
}
