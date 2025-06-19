package org.wordpress.aztec.spans;

import android.text.Editable;
import android.text.SpannableStringBuilder;
import com.google.android.gms.internal.mlkit_vision_camera.U2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* renamed from: org.wordpress.aztec.spans.x, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C5175x implements D {
    public final C5146b a;
    public int b;
    public int c;
    public int d;
    public final String e;

    public C5175x(String tag, C5146b attributes, int i) {
        Intrinsics.checkNotNullParameter(tag, "tag");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.a = attributes;
        this.b = i;
        this.c = -1;
        this.d = -1;
        this.e = tag;
    }

    @Override // org.wordpress.aztec.spans.K
    public int a() {
        return this.b;
    }

    @Override // org.wordpress.aztec.spans.O
    public final int b() {
        return this.d;
    }

    @Override // org.wordpress.aztec.spans.C
    public C5146b f() {
        return this.a;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String g() {
        return u();
    }

    @Override // org.wordpress.aztec.spans.C
    public final void h(Editable editable, int i, int i2) {
        U2.b(this, (SpannableStringBuilder) editable, i, i2);
    }

    @Override // org.wordpress.aztec.spans.O
    public final int i() {
        return this.c;
    }

    @Override // org.wordpress.aztec.spans.O
    public final void j(int i) {
        this.d = i;
    }

    @Override // org.wordpress.aztec.spans.D
    public final org.wordpress.aztec.G l() {
        return null;
    }

    @Override // org.wordpress.aztec.spans.O
    public final boolean m() {
        return i() != -1;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String n() {
        return W2.a(this);
    }

    @Override // org.wordpress.aztec.spans.O
    public final void o() {
        j(-1);
    }

    @Override // org.wordpress.aztec.spans.O
    public final void p(int i) {
        this.c = i;
    }

    @Override // org.wordpress.aztec.spans.O
    public final void q() {
        p(-1);
    }

    @Override // org.wordpress.aztec.spans.O
    public final boolean s() {
        return b() != -1;
    }

    @Override // org.wordpress.aztec.spans.K
    public void t(int i) {
        this.b = i;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.e;
    }
}
