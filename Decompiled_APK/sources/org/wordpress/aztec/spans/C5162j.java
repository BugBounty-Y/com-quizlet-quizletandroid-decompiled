package org.wordpress.aztec.spans;

import android.graphics.drawable.Drawable;
import android.text.Editable;
import com.google.android.gms.internal.mlkit_vision_camera.T2;
import java.lang.ref.WeakReference;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.AztecText;
import org.wordpress.aztec.C5146b;

/* renamed from: org.wordpress.aztec.spans.j, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5162j extends AbstractC5156d implements G, M {
    public int d;
    public final C5146b e;
    public final String f;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public C5162j(Drawable drawable, int i, C5146b attributes, AztecText aztecText) {
        super(drawable);
        Intrinsics.checkNotNullParameter(drawable, "drawable");
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        this.d = i;
        this.e = attributes;
        this.b = new WeakReference(aztecText);
        this.f = "hr";
    }

    @Override // org.wordpress.aztec.spans.K
    public final int a() {
        return this.d;
    }

    @Override // org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.e;
    }

    @Override // org.wordpress.aztec.spans.C
    public final void h(Editable output, int i, int i2) {
        Intrinsics.checkNotNullParameter(output, "output");
        T2.c(this, output, i, i2);
    }

    @Override // org.wordpress.aztec.spans.M
    public final String n() {
        throw null;
    }

    @Override // org.wordpress.aztec.spans.K
    public final void t(int i) {
        this.d = i;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.f;
    }
}
