package org.wordpress.aztec.handlers;

import android.text.Spannable;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.spans.D;

/* loaded from: classes3.dex */
public abstract class b {
    public final Class a;
    public Spannable b;
    public org.wordpress.aztec.util.d c;
    public int d;
    public int e;
    public int f;
    public boolean g;

    public b(Class clazz) {
        Intrinsics.checkNotNullParameter(clazz, "clazz");
        this.a = clazz;
        this.d = -1;
        this.f = -1;
    }

    public final org.wordpress.aztec.util.d a() {
        org.wordpress.aztec.util.d dVar = this.c;
        if (dVar != null) {
            return dVar;
        }
        Intrinsics.m("block");
        throw null;
    }

    public final Spannable b() {
        Spannable spannable = this.b;
        if (spannable != null) {
            return spannable;
        }
        Intrinsics.m("text");
        throw null;
    }

    public void c() {
    }

    public abstract void d();

    public abstract void e();

    public void f() {
    }

    public void g() {
    }

    public boolean h() {
        return this.e == ((D) a().b).a();
    }
}
