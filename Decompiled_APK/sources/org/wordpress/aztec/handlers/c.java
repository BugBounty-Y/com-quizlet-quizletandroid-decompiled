package org.wordpress.aztec.handlers;

import android.text.Spannable;
import com.google.android.gms.internal.mlkit_vision_camera.C2;
import com.google.android.gms.internal.mlkit_vision_camera.E2;
import com.google.android.gms.internal.mlkit_vision_camera.M2;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.C5160h;
import org.wordpress.aztec.spans.P;

/* loaded from: classes3.dex */
public final class c extends b {
    public final EnumC5145a h;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public c(EnumC5145a alignmentRendering) {
        super(C5160h.class);
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        this.h = alignmentRendering;
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void c() {
        if (a().b() == this.f) {
            return;
        }
        a().d(this.f);
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void d() {
        a().c();
        Spannable spannable = b();
        int i = this.d;
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        spannable.setSpan(new P(), i, i + 1, 33);
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void e() {
        a().c();
        Spannable spannable = b();
        int i = this.d;
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        spannable.setSpan(new P(), i, i + 1, 33);
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void f() {
        org.wordpress.aztec.util.d dVarA = a();
        dVarA.e(dVarA.b, this.d + 1, dVarA.a(), dVarA.a.getSpanFlags(dVarA.b));
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void g() {
        if ((this.d != a().a() - 2 || (b().charAt(a().a() - 1) != C2.g && b().charAt(a().a() - 1) != C2.i)) && this.d != b().length() - 1) {
            Spannable text = b();
            C5160h block = (C5160h) a().b;
            int i = this.d + 1;
            int iA = a().a();
            Intrinsics.checkNotNullParameter(text, "text");
            Intrinsics.checkNotNullParameter(block, "block");
            EnumC5145a alignmentRendering = this.h;
            Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
            E2.b(text, M2.d(block.a(), block.f, block.f(), alignmentRendering, block.e()), i, iA);
        }
        a().d(this.d + 1);
    }
}
