package org.wordpress.aztec.watchers.event.sequence;

import android.text.SpannableStringBuilder;
import kotlin.jvm.internal.Intrinsics;
import org.jsoup.parser.C;
import org.wordpress.aztec.spans.AztecPreformatSpan;
import org.wordpress.aztec.spans.C5154b;
import org.wordpress.aztec.spans.C5160h;
import org.wordpress.aztec.spans.C5164l;
import org.wordpress.aztec.watchers.event.text.e;

/* loaded from: classes3.dex */
public abstract class c {
    public final C a;

    public c() {
        C sequence = new C(3);
        Intrinsics.checkNotNullParameter(sequence, "sequence");
        this.a = sequence;
    }

    public static boolean c(org.wordpress.aztec.watchers.event.text.b data) {
        Intrinsics.checkNotNullParameter(data, "data");
        int i = data.b + data.c;
        int i2 = i + 1;
        SpannableStringBuilder spannableStringBuilder = data.a;
        Intrinsics.d(spannableStringBuilder);
        Object[] spans = spannableStringBuilder.getSpans(i, i2, C5164l.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(...)");
        boolean z = spans.length == 0;
        Object[] spans2 = spannableStringBuilder.getSpans(i, i2, AztecPreformatSpan.class);
        Intrinsics.checkNotNullExpressionValue(spans2, "getSpans(...)");
        boolean z2 = spans2.length == 0;
        Object[] spans3 = spannableStringBuilder.getSpans(i, i2, C5154b.class);
        Intrinsics.checkNotNullExpressionValue(spans3, "getSpans(...)");
        boolean z3 = spans3.length == 0;
        Object[] spans4 = spannableStringBuilder.getSpans(i, i2, C5160h.class);
        Intrinsics.checkNotNullExpressionValue(spans4, "getSpans(...)");
        boolean z4 = spans4.length == 0;
        boolean z5 = !z4;
        if (!z4 && spannableStringBuilder.length() > i2 && spannableStringBuilder.charAt(i2) == '\n') {
            z5 = false;
        }
        return (z && !z5 && z2 && z3) ? false : true;
    }

    public final void a(e event) {
        Intrinsics.checkNotNullParameter(event, "event");
        this.a.add(event);
    }

    public abstract org.wordpress.aztec.watchers.event.sequence.known.space.steps.c b(a aVar);

    public abstract b d(a aVar);

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:9:0x003d  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean e(org.wordpress.aztec.watchers.event.sequence.a r12) {
        /*
            r11 = this;
            r0 = 1
            java.lang.String r1 = "sequence"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r12, r1)
            int r1 = r12.size()
            r2 = 0
            r3 = r2
        Lc:
            if (r3 >= r1) goto L60
            org.jsoup.parser.C r4 = r11.a
            java.lang.Object r4 = r4.get(r3)
            java.lang.String r5 = "get(...)"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r5)
            org.wordpress.aztec.watchers.event.text.e r4 = (org.wordpress.aztec.watchers.event.text.e) r4
            java.lang.Object r6 = r12.get(r3)
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r6, r5)
            org.wordpress.aztec.watchers.event.text.e r6 = (org.wordpress.aztec.watchers.event.text.e) r6
            if (r3 <= 0) goto L3d
            int r5 = r3 + (-1)
            java.lang.Object r5 = r12.get(r5)
            org.wordpress.aztec.watchers.event.text.e r5 = (org.wordpress.aztec.watchers.event.text.e) r5
            long r7 = r5.d
            long r9 = r6.d
            long r9 = r9 - r7
            int r5 = org.wordpress.aztec.watchers.event.sequence.a.d
            r5 = 100
            long r7 = (long) r5
            int r5 = (r9 > r7 ? 1 : (r9 == r7 ? 0 : -1))
            if (r5 <= 0) goto L3d
            goto L5d
        L3d:
            org.wordpress.aztec.watchers.event.text.b r5 = r6.a
            r4.getClass()
            java.lang.String r7 = "<set-?>"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r7)
            r4.a = r5
            org.wordpress.aztec.watchers.event.text.c r5 = r6.b
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r7)
            r4.b = r5
            org.wordpress.aztec.watchers.event.text.a r5 = r6.c
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r7)
            r4.c = r5
            boolean r4 = r4.a()
            if (r4 != 0) goto L5e
        L5d:
            return r2
        L5e:
            int r3 = r3 + r0
            goto Lc
        L60:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.wordpress.aztec.watchers.event.sequence.c.e(org.wordpress.aztec.watchers.event.sequence.a):boolean");
    }
}
