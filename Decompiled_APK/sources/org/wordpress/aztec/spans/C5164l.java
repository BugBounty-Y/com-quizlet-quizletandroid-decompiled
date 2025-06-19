package org.wordpress.aztec.spans;

import android.text.Editable;
import android.text.SpannableStringBuilder;
import android.text.TextPaint;
import android.text.style.CharacterStyle;
import com.google.android.gms.internal.mlkit_vision_camera.U2;
import com.google.android.gms.internal.mlkit_vision_camera.W2;
import com.j256.ormlite.stmt.query.SimpleComparison;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

/* renamed from: org.wordpress.aztec.spans.l, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public class C5164l extends CharacterStyle implements E {
    public int a;
    public final C5146b b;
    public org.wordpress.aztec.formatting.d c;
    public final String d;
    public int e;
    public int f;

    public C5164l(int i, C5146b attributes, org.wordpress.aztec.formatting.d listItemStyle) {
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(listItemStyle, "listItemStyle");
        this.a = i;
        this.b = attributes;
        this.c = listItemStyle;
        this.d = "li";
        this.e = -1;
        this.f = -1;
    }

    @Override // org.wordpress.aztec.spans.K
    public final int a() {
        return this.a;
    }

    @Override // org.wordpress.aztec.spans.O
    public final int b() {
        return this.f;
    }

    @Override // org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.b;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String g() {
        return u();
    }

    @Override // org.wordpress.aztec.spans.C
    public final void h(Editable output, int i, int i2) {
        Intrinsics.checkNotNullParameter(output, "output");
        U2.b(this, (SpannableStringBuilder) output, i, i2);
    }

    @Override // org.wordpress.aztec.spans.O
    public final int i() {
        return this.e;
    }

    @Override // org.wordpress.aztec.spans.O
    public final void j(int i) {
        this.f = i;
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
        C5146b c5146b = this.b;
        boolean zA = c5146b.a("checked");
        if (!zA) {
            return W2.a(this);
        }
        StringBuilder sb = new StringBuilder();
        sb.append(this.d);
        int length = c5146b.getLength();
        for (int i = 0; i < length; i++) {
            String localName = c5146b.getLocalName(i);
            if (!Intrinsics.b(localName, "checked")) {
                sb.append(" ");
                sb.append(localName);
                sb.append("=\"");
                sb.append(c5146b.getValue(i));
                sb.append("\"");
            }
        }
        sb.append(SimpleComparison.GREATER_THAN_OPERATION);
        if (zA) {
            sb.append("<input type=\"checkbox\" class=\"task-list-item-checkbox\"");
            if (Intrinsics.b(c5146b.getValue("checked"), "true")) {
                sb.append(" checked");
            }
            sb.append(" /");
        }
        String string = sb.toString();
        Intrinsics.checkNotNullExpressionValue(string, "toString(...)");
        return string;
    }

    @Override // org.wordpress.aztec.spans.O
    public final void o() {
        j(-1);
    }

    @Override // org.wordpress.aztec.spans.O
    public final void p(int i) {
        this.e = i;
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
    public final void t(int i) {
        this.a = i;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.d;
    }

    @Override // android.text.style.CharacterStyle
    public final void updateDrawState(TextPaint tp) {
        Intrinsics.checkNotNullParameter(tp, "tp");
        boolean zB = Intrinsics.b(this.b.getValue("checked"), "true");
        if (this.c.a) {
            tp.setStrikeThruText(zB);
        }
        int i = this.c.b;
        if (i == 0 || !zB) {
            return;
        }
        tp.setColor(i);
    }
}
