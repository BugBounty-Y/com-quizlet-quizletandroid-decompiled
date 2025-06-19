package org.wordpress.aztec.spans;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.text.Layout;
import android.text.Spanned;
import com.quizlet.db.data.models.persisted.fields.DBUserFields;
import com.quizlet.quizletandroid.R;
import java.lang.ref.WeakReference;
import kotlin.Metadata;
import kotlin.Pair;
import kotlin.collections.C4933y;
import kotlin.collections.CollectionsKt;
import kotlin.jvm.internal.Intrinsics;
import org.wordpress.aztec.C5146b;

@Metadata
/* loaded from: classes3.dex */
public class AztecTaskListSpan extends AztecListSpan {
    public int d;
    public final C5146b e;
    public org.wordpress.aztec.formatting.e f;
    public kotlin.jvm.internal.r g;
    public boolean h;
    public final WeakReference i;
    public final String j;
    public final org.wordpress.aztec.x k;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AztecTaskListSpan(int i, C5146b attributes, Context context, org.wordpress.aztec.formatting.e listStyle) {
        super(listStyle.e);
        Intrinsics.checkNotNullParameter(attributes, "attributes");
        Intrinsics.checkNotNullParameter(context, "context");
        Intrinsics.checkNotNullParameter(listStyle, "listStyle");
        this.d = i;
        this.e = attributes;
        this.f = listStyle;
        this.g = null;
        this.i = new WeakReference(context);
        this.j = "ul";
        this.k = org.wordpress.aztec.x.j;
    }

    @Override // org.wordpress.aztec.spans.AztecListSpan, org.wordpress.aztec.spans.K
    public final int a() {
        return this.d;
    }

    @Override // android.text.style.LeadingMarginSpan.Standard, android.text.style.LeadingMarginSpan
    public final void drawLeadingMargin(Canvas c, Paint p, int i, int i2, int i3, int i4, int i5, CharSequence text, int i6, int i7, boolean z, Layout l) {
        Integer numV;
        C5146b c5146b;
        Resources resources;
        Intrinsics.checkNotNullParameter(c, "c");
        Intrinsics.checkNotNullParameter(p, "p");
        Intrinsics.checkNotNullParameter(text, "text");
        Intrinsics.checkNotNullParameter(l, "l");
        if (z) {
            WeakReference weakReference = this.i;
            if (weakReference.get() == null) {
                return;
            }
            Spanned spanned = (Spanned) text;
            int spanStart = spanned.getSpanStart(this);
            int spanEnd = spanned.getSpanEnd(this);
            if (spanStart > i6 || i6 > spanEnd || spanStart > i7 || i7 > spanEnd || (numV = v(i7, text)) == null) {
                return;
            }
            int iIntValue = numV.intValue();
            Paint.Style style = p.getStyle();
            int color = p.getColor();
            p.setColor(this.f.a);
            p.setStyle(Paint.Style.FILL);
            double d = (p.getFontMetrics().bottom - p.getFontMetrics().top) * 0.8d;
            float f = (this.f.b * i2 * 1.0f) + i;
            Context context = (Context) weakReference.get();
            String value = null;
            Drawable drawable = (context == null || (resources = context.getResources()) == null) ? null : resources.getDrawable(R.drawable.ic_checkbox, null);
            int i8 = (int) f;
            Spanned spanned2 = (Spanned) text;
            Object[] spans = spanned2.getSpans(spanned2.getSpanStart(this), spanned2.getSpanEnd(this), C5164l.class);
            Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
            C5164l c5164l = (C5164l) CollectionsKt.O(iIntValue - 1, C4933y.K(spans, new androidx.camera.core.streamsharing.a(text, 10)));
            if (c5164l != null && (c5146b = c5164l.b) != null) {
                value = c5146b.getValue("checked");
            }
            if (Intrinsics.b(value, "true")) {
                if (drawable != null) {
                    drawable.setState(new int[]{android.R.attr.state_checked});
                }
            } else if (drawable != null) {
                drawable.setState(new int[0]);
            }
            Pair pair = i2 > 0 ? new Pair(Double.valueOf(0.8d), Double.valueOf(0.2d)) : new Pair(Double.valueOf(0.2d), Double.valueOf(0.8d));
            double dDoubleValue = ((Number) pair.a).doubleValue();
            double dDoubleValue2 = ((Number) pair.b).doubleValue();
            if (drawable != null) {
                double d2 = i8;
                int i9 = (int) (d2 - (dDoubleValue * d));
                double d3 = i4;
                drawable.setBounds(i9 >= 0 ? i9 : 0, (int) (d3 - (d * 0.8d)), (int) ((dDoubleValue2 * d) + d2), (int) ((d * 0.2d) + d3));
            }
            if (drawable != null) {
                drawable.draw(c);
            }
            p.setColor(color);
            p.setStyle(style);
        }
    }

    @Override // org.wordpress.aztec.spans.C
    public final C5146b f() {
        return this.e;
    }

    @Override // android.text.style.LeadingMarginSpan.Standard, android.text.style.LeadingMarginSpan
    public final int getLeadingMargin(boolean z) {
        org.wordpress.aztec.formatting.e eVar = this.f;
        return (eVar.d * 2) + eVar.b + eVar.c;
    }

    @Override // org.wordpress.aztec.spans.D
    public final org.wordpress.aztec.G l() {
        return this.k;
    }

    @Override // org.wordpress.aztec.spans.AztecListSpan, org.wordpress.aztec.spans.M
    public final String n() {
        C5146b c5146b = this.e;
        Intrinsics.checkNotNullParameter(c5146b, "<this>");
        if (!c5146b.a(DBUserFields.Names.USER_UPGRADE_TYPE)) {
            c5146b.d(DBUserFields.Names.USER_UPGRADE_TYPE, "task-list");
        }
        return this.j + ' ' + c5146b;
    }

    @Override // org.wordpress.aztec.spans.K
    public final void t(int i) {
        this.d = i;
    }

    @Override // org.wordpress.aztec.spans.M
    public final String u() {
        return this.j;
    }
}
