package org.wordpress.aztec.handlers;

import android.text.Spannable;
import com.google.android.gms.internal.mlkit_vision_camera.F2;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.EnumC5145a;
import org.wordpress.aztec.spans.C5164l;
import org.wordpress.aztec.spans.C5174w;
import org.wordpress.aztec.spans.P;

/* loaded from: classes3.dex */
public final class e extends b {
    public final EnumC5145a h;
    public final org.wordpress.aztec.formatting.d i;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public e(EnumC5145a alignmentRendering, org.wordpress.aztec.formatting.d listItemStyle) {
        super(C5164l.class);
        Intrinsics.checkNotNullParameter(alignmentRendering, "alignmentRendering");
        Intrinsics.checkNotNullParameter(listItemStyle, "listItemStyle");
        this.h = alignmentRendering;
        this.i = listItemStyle;
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void c() {
        if (a().b() == this.f) {
            return;
        }
        Spannable spannableB = b();
        int i = this.f;
        F2.f(spannableB, i, i + 1, ((C5164l) a().b).a, this.h, this.i);
        a().d(this.f);
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void d() {
        a().c();
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void e() {
        org.wordpress.aztec.util.d dVarD = C5174w.d(b(), a());
        if (dVarD == null || (dVarD.a() == 0 && dVarD.b() == 0)) {
            a().c();
        } else if (a().a() == dVarD.a()) {
            a().c();
        }
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void f() {
        Spannable spannableB = b();
        int i = this.d;
        F2.f(spannableB, i, i + 1, ((C5164l) a().b).a, this.h, this.i);
        org.wordpress.aztec.util.d dVarA = a();
        dVarA.e(dVarA.b, this.d + 1, dVarA.a(), dVarA.a.getSpanFlags(dVarA.b));
    }

    @Override // org.wordpress.aztec.handlers.b
    public final void g() {
        int i = this.d + 1;
        Spannable spannable = b();
        int i2 = this.d;
        Intrinsics.checkNotNullParameter(spannable, "spannable");
        Object[] spans = spannable.getSpans(i2, i2 + 1, P.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        Intrinsics.checkNotNullParameter(spans, "<this>");
        if (spans.length != 0) {
            i = this.d;
        }
        int i3 = i;
        F2.f(b(), i3, a().a(), ((C5164l) a().b).a, this.h, this.i);
        a().d(i3);
    }
}
